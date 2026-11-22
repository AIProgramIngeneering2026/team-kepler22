// Package runner выполняет Job в фоне по модели pull (ADR-0001): обработчики сами забирают
// Job из хранилища, поэтому Job не теряется при перезапуске, а параллельно работает
// не больше Job, чем обработчиков.
package runner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/dispatcher"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
)

// PollInterval нужен только для Job, оставшихся после перезапуска: о новых Job будит Notify.
const PollInterval = time.Second

type Runner struct {
	repo    job.Repository
	disp    *dispatcher.Dispatcher
	log     *slog.Logger
	wake    chan struct{}
	mu      sync.Mutex
	running map[string]inFlight
	wg      sync.WaitGroup
}

// inFlight это копия Job, с которой работает обработчик, и отмена его контекста.
type inFlight struct {
	job    *job.Job
	cancel context.CancelFunc
}

func New(repo job.Repository, disp *dispatcher.Dispatcher, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Runner{
		repo:    repo,
		disp:    disp,
		log:     log,
		wake:    make(chan struct{}, 1),
		running: make(map[string]inFlight),
	}
}

// Start запускает обработчики до отмены ctx. Job в работе при этом станут failed (interrupted),
// а Job в created останутся в хранилище до следующего запуска.
func (r *Runner) Start(ctx context.Context, workers int) {
	for i := 0; i < max(workers, 1); i++ {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.work(ctx)
		}()
	}
}

// Wait ждёт остановки обработчиков после отмены ctx, переданного в Start.
func (r *Runner) Wait() { r.wg.Wait() }

// Notify будит свободный обработчик, не блокируясь.
func (r *Runner) Notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// RecoverInterrupted вызывается при запуске до Start: Job, оставшиеся в running, уже никто не выполнит.
func (r *Runner) RecoverInterrupted(ctx context.Context) error {
	jobs, err := r.repo.ListByStatus(ctx, job.Running)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if err := j.Fail(job.Error{Code: job.Interrupted, Message: "сервис перезапущен"}); err != nil {
			return err
		}
		if err := r.repo.Update(ctx, j, job.Running); err != nil && !errors.Is(err, job.ErrConflict) {
			return err
		}
	}
	return nil
}

// CancelRunning отменяет Job, если его выполняет обработчик этого процесса (ok = true).
// Отменяется копия обработчика, поэтому Dispatcher останавливается и уже не завершит Job.
func (r *Runner) CancelRunning(ctx context.Context, id string) (j *job.Job, ok bool, err error) {
	f, ok := r.inFlight(id)
	if !ok {
		return nil, false, nil
	}
	if err := f.job.Cancel(); err != nil {
		return nil, true, err
	}
	f.cancel()
	err = r.repo.Update(ctx, f.job, job.Running)
	if errors.Is(err, job.ErrConflict) {
		// Обработчик мог сохранить ту же отменённую копию раньше нас.
		if stored, getErr := r.repo.Get(ctx, id); getErr == nil && stored.Status() == job.Cancelled {
			return stored, true, nil
		}
	}
	if err != nil {
		return nil, true, err
	}
	return f.job, true, nil
}

func (r *Runner) work(ctx context.Context) {
	for ctx.Err() == nil {
		j, err := r.repo.ClaimNext(ctx)
		if err == nil {
			r.Notify() // в очереди могут быть ещё Job
			r.process(ctx, j)
			continue
		}
		if !errors.Is(err, job.ErrNoPendingJob) {
			r.log.Error("не удалось взять Job из хранилища", "err", err)
		}
		r.idle(ctx)
	}
}

func (r *Runner) idle(ctx context.Context) {
	t := time.NewTimer(PollInterval)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-r.wake:
	case <-t.C:
	}
}

func (r *Runner) process(ctx context.Context, j *job.Job) {
	runCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.running[j.ID()] = inFlight{job: j, cancel: cancel}
	r.mu.Unlock()
	defer r.forget(j.ID())

	if err := r.disp.Run(runCtx, j); err != nil {
		r.log.Info("Job не запущен", "job_id", j.ID(), "err", err)
	}
	r.save(j)
}

// save не перезаписывает Job, который изменили снаружи, например отменили из другого процесса.
func (r *Runner) save(j *job.Job) {
	err := r.repo.Update(context.Background(), j, job.Running)
	switch {
	case err == nil:
	case errors.Is(err, job.ErrConflict):
		r.log.Info("Job изменён снаружи, результат отброшен", "job_id", j.ID())
	default:
		r.log.Error("не удалось сохранить Job", "job_id", j.ID(), "err", err)
	}
}

func (r *Runner) inFlight(id string) (inFlight, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.running[id]
	return f, ok
}

func (r *Runner) forget(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.running[id]; ok {
		f.cancel()
		delete(r.running, id)
	}
}
