// Package service это Job Service: проверяет запрос, создаёт, читает и отменяет Job.
// Выполняет Job отдельный Scheduler (runner.Runner). По контракту Tool параметры запроса
// проверяет этот сервис, а не Tool.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/registry"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

const MaxComponents = 10000

// cancelAttempts ограничивает повторы Cancel, если Job меняет состояние прямо во время отмены.
const cancelAttempts = 3

var ErrInvalidParams = errors.New("invalid_params")

// Problem говорит, что не так с запросом. Как показать это клиенту, решает HTTP-адаптер.
type Problem string

const (
	NoComponents         Problem = "no_components"
	TooManyComponents    Problem = "too_many_components"
	ComponentWithoutName Problem = "component_without_name"
	NoSources            Problem = "no_sources"
	DuplicateSource      Problem = "duplicate_source"
	UnknownSource        Problem = "unknown_source"
	NoFinder             Problem = "no_finder"
)

// RequestError указывает неверное поле Request, например "components[1].name" или "sources[0]".
// errors.Is даёт registry.ErrUnknownTool для UnknownSource и ErrInvalidParams для остального.
type RequestError struct {
	Problem Problem
	Field   string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%v: %s: %s", e.Unwrap(), e.Field, e.Problem)
}

func (e *RequestError) Unwrap() error {
	if e.Problem == UnknownSource {
		return registry.ErrUnknownTool
	}
	return ErrInvalidParams
}

func reject(p Problem, field string) error { return &RequestError{Problem: p, Field: field} }

type Request struct {
	Components []vuln.Component
	Sources    []string // nil значит все зарегистрированные источники
}

// Scheduler выполняет Job в фоне.
type Scheduler interface {
	Notify()
	// CancelRunning отменяет Job, если его выполняет этот процесс; иначе ok = false.
	CancelRunning(ctx context.Context, id string) (j *job.Job, ok bool, err error)
}

type Service struct {
	repo  job.Repository
	reg   *registry.Registry
	sched Scheduler
	newID func() string
}

func New(repo job.Repository, reg *registry.Registry, sched Scheduler) *Service {
	return &Service{repo: repo, reg: reg, sched: sched, newID: randomID}
}

// Submit сохраняет Job в created. Выполнит его свободный обработчик.
func (s *Service) Submit(ctx context.Context, req Request) (*job.Job, error) {
	sources, err := s.validate(req)
	if err != nil {
		return nil, err
	}
	j, err := job.New(s.newID(), sources, req.Components)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, j); err != nil {
		return nil, err
	}
	s.sched.Notify()
	return j, nil
}

func (s *Service) Get(ctx context.Context, id string) (*job.Job, error) {
	return s.repo.Get(ctx, id)
}

// Cancel для завершённого Job возвращает job.ErrInvalidTransition.
func (s *Service) Cancel(ctx context.Context, id string) (*job.Job, error) {
	for attempt := 0; attempt < cancelAttempts; attempt++ {
		j, err := s.cancelOnce(ctx, id)
		if !errors.Is(err, job.ErrConflict) {
			return j, err
		}
	}
	return nil, fmt.Errorf("%w: job %s меняется во время отмены", job.ErrConflict, id)
}

func (s *Service) cancelOnce(ctx context.Context, id string) (*job.Job, error) {
	if j, ok, err := s.sched.CancelRunning(ctx, id); ok {
		return j, err
	}
	j, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	from := j.Status()
	if err := j.Cancel(); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, j, from); err != nil {
		return nil, err
	}
	return j, nil
}

func (s *Service) validate(req Request) ([]string, error) {
	if err := validateComponents(req.Components); err != nil {
		return nil, err
	}
	sources := req.Sources
	if sources == nil {
		sources = s.reg.Names()
	}
	if err := s.validateSources(sources); err != nil {
		return nil, err
	}
	return append([]string(nil), sources...), nil
}

func validateComponents(components []vuln.Component) error {
	switch {
	case len(components) == 0:
		return reject(NoComponents, "components")
	case len(components) > MaxComponents:
		return reject(TooManyComponents, "components")
	}
	for i, c := range components {
		if c.Name == "" {
			return reject(ComponentWithoutName, fmt.Sprintf("components[%d].name", i))
		}
	}
	return nil
}

func (s *Service) validateSources(sources []string) error {
	if len(sources) == 0 {
		return reject(NoSources, "sources")
	}
	seen := map[string]bool{}
	hasFinder := false
	for i, name := range sources {
		field := fmt.Sprintf("sources[%d]", i)
		if seen[name] {
			return reject(DuplicateSource, field)
		}
		seen[name] = true
		t, err := s.reg.Get(name)
		if err != nil {
			return reject(UnknownSource, field)
		}
		hasFinder = hasFinder || t.Role() == tool.Finder
	}
	if !hasFinder {
		return reject(NoFinder, "sources")
	}
	return nil
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
