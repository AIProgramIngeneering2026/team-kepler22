// Package dispatcher выполняет взятый в работу Job: запускает Tool из Registry и решает итоговое
// состояние. Конкретных Tool Dispatcher не знает, он видит только имя и роль.
package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/registry"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

var errToolPanic = errors.New("tool panic")

// ErrNotRunning: Job отменили сразу после того, как обработчик взял его из хранилища.
var ErrNotRunning = errors.New("job_not_running")

type Dispatcher struct {
	reg *registry.Registry
	log *slog.Logger
}

func New(reg *registry.Registry, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Dispatcher{reg: reg, log: log}
}

// Run доводит Job из running до done, partial или failed: сначала все Finder, потом все Enricher.
// Если Job отменили во время работы, результат отбрасывается.
func (d *Dispatcher) Run(ctx context.Context, j *job.Job) error {
	if s := j.Status(); s != job.Running {
		return fmt.Errorf("%w: job %s в состоянии %s", ErrNotRunning, j.ID(), s)
	}
	r := &run{d: d, ctx: ctx, job: j, log: d.log.With("job_id", j.ID())}
	finders, enrichers, ok := r.splitByRole()
	if ok && r.runFinders(finders) && r.runEnrichers(enrichers) {
		r.finish()
	}
	return nil
}

// run это одно выполнение Job. Шаги возвращают false, если Job уже переведён в конечное состояние.
type run struct {
	d      *Dispatcher
	ctx    context.Context
	job    *job.Job
	log    *slog.Logger
	report job.Report
}

func (r *run) splitByRole() (finders, enrichers []tool.Tool, ok bool) {
	for _, name := range r.job.Sources() {
		t, err := r.d.reg.Get(name)
		if err != nil {
			r.fail(job.Error{Code: job.InternalError, Message: err.Error(), Source: name})
			return nil, nil, false
		}
		if t.Role() == tool.Finder {
			finders = append(finders, t)
		} else {
			enrichers = append(enrichers, t)
		}
	}
	return finders, enrichers, true
}

func (r *run) runFinders(finders []tool.Tool) bool {
	in := tool.Input{Components: r.job.Components()}
	for _, t := range finders {
		res, err := call(r.ctx, t, in)
		if err != nil {
			r.onError(t, err)
			return false
		}
		r.report.Findings = append(r.report.Findings, res.Findings...)
		r.report.Skipped = append(r.report.Skipped, res.Skipped...)
		r.report.DataDate = oldest(r.report.DataDate, res.DataDate)
	}
	return true
}

// runEnrichers: недоступный Enricher не валит Job, а попадает в MissingSources (partial).
func (r *run) runEnrichers(enrichers []tool.Tool) bool {
	for _, t := range enrichers {
		res, err := call(r.ctx, t, tool.Input{Findings: vuln.CloneAll(r.report.Findings)})
		switch {
		case err == nil:
		case errors.Is(err, tool.ErrSourceUnavailable), errors.Is(err, tool.ErrBadResponse):
			r.log.Warn("источник не ответил, отчёт будет неполным", "tool", t.Name(), "err", err)
			r.report.MissingSources = append(r.report.MissingSources, t.Name())
			continue
		default:
			r.onError(t, err)
			return false
		}
		if len(res.Findings) != len(r.report.Findings) {
			r.fail(job.Error{Code: job.InternalError, Source: t.Name(),
				Message: fmt.Sprintf("Enricher вернул %d находок вместо %d", len(res.Findings), len(r.report.Findings))})
			return false
		}
		r.report.Findings = res.Findings
		r.report.DataDate = oldest(r.report.DataDate, res.DataDate)
	}
	return true
}

func (r *run) finish() {
	if r.ctx.Err() != nil {
		r.onCancel()
		return
	}
	r.apply(r.job.Finish(r.report))
}

// onError переводит ошибку Tool в состояние Job по таблице из docs/tool-contract.md.
func (r *run) onError(t tool.Tool, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		r.onCancel()
	case errors.Is(err, tool.ErrSourceUnavailable):
		r.fail(job.Error{Code: job.SourceUnavailable, Source: t.Name(), Message: err.Error()})
	case errors.Is(err, tool.ErrBadResponse):
		r.fail(job.Error{Code: job.BadSourceResponse, Source: t.Name(), Message: err.Error()})
	default:
		r.log.Error("ошибка в Tool", "tool", t.Name(), "err", err)
		r.fail(job.Error{Code: job.InternalError, Source: t.Name(), Message: "внутренняя ошибка"})
	}
}

// onCancel: если Job всё ещё running, его не отменял пользователь, а прервала остановка сервиса.
func (r *run) onCancel() {
	if r.job.Status() == job.Running {
		r.fail(job.Error{Code: job.Interrupted, Message: "работа прервана"})
		return
	}
	r.log.Info("Job отменён, результат отброшен", "status", r.job.Status())
}

func (r *run) fail(e job.Error) {
	r.apply(r.job.Fail(e))
}

// apply: отклонённый переход нормален, если Job отменили, пока работали Tool.
func (r *run) apply(err error) {
	switch {
	case err == nil:
		r.log.Info("Job завершён", "status", r.job.Status())
	case errors.Is(err, job.ErrInvalidTransition):
		r.log.Info("переход отклонён, результат отброшен", "err", err)
	default:
		r.log.Error("не удалось завершить Job", "err", err)
	}
}

// call превращает панику внутри Tool в ошибку.
func call(ctx context.Context, t tool.Tool, in tool.Input) (res tool.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: %s: %v", errToolPanic, t.Name(), p)
		}
	}()
	return t.Run(ctx, in)
}

func oldest(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil || a.Before(*b) {
		return a
	}
	return b
}
