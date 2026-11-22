// Package job описывает Job и разрешённые переходы его состояний (docs/architecture.md).
package job

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

type Status string

const (
	Created   Status = "created"
	Running   Status = "running"
	Done      Status = "done"
	Partial   Status = "partial"
	Failed    Status = "failed"
	Cancelled Status = "cancelled"
)

// Всё, чего нет в таблице, запрещено.
var transitions = map[Status]map[Status]bool{
	Created: {Running: true, Cancelled: true},
	Running: {Done: true, Partial: true, Failed: true, Cancelled: true},
}

func (s Status) Valid() bool {
	switch s {
	case Created, Running, Done, Partial, Failed, Cancelled:
		return true
	}
	return false
}

func (s Status) Terminal() bool {
	return s == Done || s == Partial || s == Failed || s == Cancelled
}

func CanTransition(from, to Status) bool {
	return transitions[from][to]
}

var (
	ErrInvalidTransition = errors.New("invalid_transition")
	ErrInvalidJob        = errors.New("invalid_job")
	ErrNotFound          = errors.New("job_not_found")
	ErrNoPendingJob      = errors.New("no_pending_job")
	ErrConflict          = errors.New("job_conflict")
)

type TransitionError struct {
	ID       string
	From, To Status
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("job %s: переход %s → %s запрещён", e.ID, e.From, e.To)
}

func (e *TransitionError) Is(target error) bool { return target == ErrInvalidTransition }

type ErrorCode string

const (
	SourceUnavailable ErrorCode = "source_unavailable"
	BadSourceResponse ErrorCode = "bad_source_response"
	Interrupted       ErrorCode = "interrupted"
	InternalError     ErrorCode = "internal_error"
)

func (c ErrorCode) valid() bool {
	switch c {
	case SourceUnavailable, BadSourceResponse, Interrupted, InternalError:
		return true
	}
	return false
}

type Error struct {
	Code    ErrorCode
	Message string
	Source  string // имя Tool, если виноват источник
}

type Report struct {
	Findings       []vuln.Finding
	Skipped        []vuln.Skipped
	MissingSources []string   // не ответившие Enricher; непустой список значит partial
	DataDate       *time.Time // дата самых старых данных из кэша
}

func (r Report) clone() Report {
	c := Report{
		Findings:       vuln.CloneAll(r.Findings),
		Skipped:        append([]vuln.Skipped(nil), r.Skipped...),
		MissingSources: append([]string(nil), r.MissingSources...),
	}
	if r.DataDate != nil {
		d := *r.DataDate
		c.DataDate = &d
	}
	return c
}

// Job это одна проверка SBOM. Состояние меняется только методами, которые проверяют переход.
type Job struct {
	mu         sync.RWMutex
	id         string
	sources    []string
	components []vuln.Component
	status     Status
	createdAt  time.Time
	updatedAt  time.Time
	report     *Report
	err        *Error
}

func New(id string, sources []string, components []vuln.Component) (*Job, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: пустой id", ErrInvalidJob)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("%w: не указаны источники", ErrInvalidJob)
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("%w: нет компонентов SBOM", ErrInvalidJob)
	}
	now := time.Now().UTC()
	return &Job{
		id:         id,
		sources:    append([]string(nil), sources...),
		components: append([]vuln.Component(nil), components...),
		status:     Created,
		createdAt:  now,
		updatedAt:  now,
	}, nil
}

func (j *Job) Start() error {
	return j.transition(Running, nil)
}

// Finish переводит Job в partial, если какой-то Enricher не ответил, иначе в done.
func (j *Job) Finish(r Report) error {
	to := Done
	if len(r.MissingSources) > 0 {
		to = Partial
	}
	rep := r.clone()
	return j.transition(to, func() { j.report = &rep })
}

func (j *Job) Fail(e Error) error {
	if !e.Code.valid() {
		return fmt.Errorf("%w: неизвестный код ошибки %q", ErrInvalidJob, e.Code)
	}
	return j.transition(Failed, func() { j.err = &e })
}

func (j *Job) Cancel() error {
	return j.transition(Cancelled, nil)
}

func (j *Job) transition(to Status, apply func()) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !CanTransition(j.status, to) {
		return &TransitionError{ID: j.id, From: j.status, To: to}
	}
	if apply != nil {
		apply()
	}
	j.status = to
	j.updatedAt = time.Now().UTC()
	return nil
}

func (j *Job) ID() string { return j.id }

func (j *Job) Status() Status {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.status
}

func (j *Job) Sources() []string {
	return append([]string(nil), j.sources...)
}

func (j *Job) Components() []vuln.Component {
	return append([]vuln.Component(nil), j.components...)
}

// Snapshot это независимая копия Job для чтения и хранения.
type Snapshot struct {
	ID         string
	Sources    []string
	Components []vuln.Component
	Status     Status
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Report     *Report
	Error      *Error
}

func (j *Job) Snapshot() Snapshot {
	j.mu.RLock()
	defer j.mu.RUnlock()
	s := Snapshot{
		ID:         j.id,
		Sources:    j.Sources(),
		Components: j.Components(),
		Status:     j.status,
		CreatedAt:  j.createdAt,
		UpdatedAt:  j.updatedAt,
	}
	if j.report != nil {
		r := j.report.clone()
		s.Report = &r
	}
	if j.err != nil {
		e := *j.err
		s.Error = &e
	}
	return s
}

// Restore проверяет, что данные не противоречат состоянию: подменённая в хранилище запись
// не должна попасть в ядро.
func Restore(s Snapshot) (*Job, error) {
	if s.ID == "" || len(s.Sources) == 0 || len(s.Components) == 0 {
		return nil, fmt.Errorf("%w: пустой id, список источников или компонентов", ErrInvalidJob)
	}
	if !s.Status.Valid() {
		return nil, fmt.Errorf("%w: неизвестное состояние %q", ErrInvalidJob, s.Status)
	}
	hasReport, hasErr := s.Report != nil, s.Error != nil
	ok := false
	switch s.Status {
	case Created, Running, Cancelled:
		ok = !hasReport && !hasErr
	case Done:
		ok = hasReport && !hasErr && len(s.Report.MissingSources) == 0
	case Partial:
		ok = hasReport && !hasErr && len(s.Report.MissingSources) > 0
	case Failed:
		ok = !hasReport && hasErr && s.Error.Code.valid()
	}
	if !ok {
		return nil, fmt.Errorf("%w: данные не соответствуют состоянию %s", ErrInvalidJob, s.Status)
	}
	j := &Job{
		id:         s.ID,
		sources:    append([]string(nil), s.Sources...),
		components: append([]vuln.Component(nil), s.Components...),
		status:     s.Status,
		createdAt:  s.CreatedAt,
		updatedAt:  s.UpdatedAt,
	}
	if hasReport {
		r := s.Report.clone()
		j.report = &r
	}
	if hasErr {
		e := *s.Error
		j.err = &e
	}
	return j, nil
}

// Repository работает с копиями, как настоящая база: изменения полученного *Job
// никто не видит, пока они не сохранены через Update.
type Repository interface {
	// Create возвращает ErrConflict, если id уже занят.
	Create(ctx context.Context, j *Job) error
	// Update сохраняет Job, только если в хранилище он всё ещё в состоянии from, иначе ErrConflict.
	// Так обработчик не перезапишет отмену, записанную другим участником.
	Update(ctx context.Context, j *Job, from Status) error
	Get(ctx context.Context, id string) (*Job, error)
	ListByStatus(ctx context.Context, s Status) ([]*Job, error)
	// ClaimNext атомарно переводит самый старый Job из created в running и возвращает его.
	// Если брать нечего, возвращает ErrNoPendingJob.
	ClaimNext(ctx context.Context) (*Job, error)
}
