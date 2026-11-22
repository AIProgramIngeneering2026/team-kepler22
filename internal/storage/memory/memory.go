// Package memory хранит Job в памяти процесса для тестов и прототипа. Как и настоящая база,
// оно хранит снимки и отдаёт копии, поэтому ядро не может полагаться на общий объект в памяти.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
)

type Repository struct {
	mu    sync.Mutex
	jobs  map[string]job.Snapshot
	order []string // id в порядке создания, по нему ClaimNext берёт самый старый Job
}

var _ job.Repository = (*Repository)(nil)

func New() *Repository {
	return &Repository{jobs: make(map[string]job.Snapshot)}
}

func (r *Repository) Create(_ context.Context, j *job.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.jobs[j.ID()]; ok {
		return job.ErrConflict
	}
	r.jobs[j.ID()] = j.Snapshot()
	r.order = append(r.order, j.ID())
	return nil
}

func (r *Repository) Update(_ context.Context, j *job.Job, from job.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.jobs[j.ID()]
	if !ok {
		return job.ErrNotFound
	}
	if stored.Status != from {
		return job.ErrConflict
	}
	r.jobs[j.ID()] = j.Snapshot()
	return nil
}

func (r *Repository) Get(_ context.Context, id string) (*job.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.jobs[id]
	if !ok {
		return nil, job.ErrNotFound
	}
	return job.Restore(s)
}

func (r *Repository) ListByStatus(_ context.Context, status job.Status) ([]*job.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0)
	for id, s := range r.jobs {
		if s.Status == status {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := make([]*job.Job, 0, len(ids))
	for _, id := range ids {
		j, err := job.Restore(r.jobs[id])
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

// ClaimNext берёт самый старый Job в состоянии created, переводит его в running и сохраняет.
// Весь поиск идёт под одной блокировкой, поэтому два обработчика не возьмут один Job.
func (r *Repository) ClaimNext(_ context.Context) (*job.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.order {
		if r.jobs[id].Status != job.Created {
			continue
		}
		j, err := job.Restore(r.jobs[id])
		if err != nil {
			return nil, err
		}
		if err := j.Start(); err != nil {
			return nil, err
		}
		r.jobs[id] = j.Snapshot()
		return j, nil
	}
	return nil, job.ErrNoPendingJob
}
