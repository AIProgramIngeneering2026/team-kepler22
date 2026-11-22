package memory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/storage/memory"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

var (
	ctx   = context.Background()
	comps = []vuln.Component{{Name: "lodash", Version: "4.17.20"}}
)

func create(t *testing.T, r *memory.Repository, id string) *job.Job {
	t.Helper()
	j, err := job.New(id, []string{"osv"}, comps)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, j); err != nil {
		t.Fatal(err)
	}
	return j
}

func statusOf(t *testing.T, r *memory.Repository, id string) job.Status {
	t.Helper()
	j, err := r.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return j.Status()
}

func TestCreateTwiceConflicts(t *testing.T) {
	r := memory.New()
	j := create(t, r, "job-1")
	if err := r.Create(ctx, j); !errors.Is(err, job.ErrConflict) {
		t.Fatalf("ожидали ErrConflict, получили %v", err)
	}
}

// Хранилище отдаёт копии, как база: изменение полученного Job не видно, пока его не сохранили.
func TestGetReturnsCopy(t *testing.T) {
	r := memory.New()
	orig := create(t, r, "job-1")
	_ = orig.Cancel()
	if got := statusOf(t, r, "job-1"); got != job.Created {
		t.Fatalf("изменение исходного объекта попало в хранилище: %s", got)
	}

	copy1, _ := r.Get(ctx, "job-1")
	_ = copy1.Start()
	if got := statusOf(t, r, "job-1"); got != job.Created {
		t.Fatalf("изменение копии попало в хранилище без Update: %s", got)
	}
}

func TestUpdateChecksExpectedStatus(t *testing.T) {
	r := memory.New()
	create(t, r, "job-1")

	j, _ := r.Get(ctx, "job-1")
	_ = j.Cancel()
	if err := r.Update(ctx, j, job.Running); !errors.Is(err, job.ErrConflict) {
		t.Fatalf("ожидали ErrConflict при неверном from, получили %v", err)
	}
	if err := r.Update(ctx, j, job.Created); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := statusOf(t, r, "job-1"); got != job.Cancelled {
		t.Fatalf("ожидали cancelled, получили %s", got)
	}
	if err := r.Update(ctx, j, job.Created); !errors.Is(err, job.ErrConflict) {
		t.Fatalf("повторный Update из created должен дать ErrConflict, получили %v", err)
	}
}

func TestUpdateUnknownJob(t *testing.T) {
	j, _ := job.New("ghost", []string{"osv"}, comps)
	if err := memory.New().Update(ctx, j, job.Created); !errors.Is(err, job.ErrNotFound) {
		t.Fatalf("ожидали ErrNotFound, получили %v", err)
	}
}

// Главный сценарий: Job отменили, пока обработчик работал со своей копией.
// Сохранение обработчика не должно перезаписать отмену.
func TestWorkerCannotOverwriteCancel(t *testing.T) {
	r := memory.New()
	create(t, r, "job-1")

	worker, err := r.ClaimNext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := r.Get(ctx, "job-1")
	_ = user.Cancel()
	if err := r.Update(ctx, user, job.Running); err != nil {
		t.Fatalf("отмена: %v", err)
	}

	_ = worker.Finish(job.Report{})
	if err := r.Update(ctx, worker, job.Running); !errors.Is(err, job.ErrConflict) {
		t.Fatalf("ожидали ErrConflict, получили %v", err)
	}
	if got := statusOf(t, r, "job-1"); got != job.Cancelled {
		t.Fatalf("отмена перезаписана: %s", got)
	}
}

func TestClaimNextEmpty(t *testing.T) {
	if _, err := memory.New().ClaimNext(ctx); !errors.Is(err, job.ErrNoPendingJob) {
		t.Fatalf("ожидали ErrNoPendingJob, получили %v", err)
	}
}

// Job берутся в порядке создания, отменённые пропускаются, взятый Job уже running и в хранилище тоже.
func TestClaimNextOrderAndSkip(t *testing.T) {
	r := memory.New()
	create(t, r, "b-first")
	create(t, r, "a-second")
	create(t, r, "c-third")
	cancelled, _ := r.Get(ctx, "a-second")
	_ = cancelled.Cancel()
	_ = r.Update(ctx, cancelled, job.Created)

	for _, want := range []string{"b-first", "c-third"} {
		j, err := r.ClaimNext(ctx)
		if err != nil || j.ID() != want || j.Status() != job.Running || statusOf(t, r, want) != job.Running {
			t.Fatalf("ожидали %s в running, получили %v %v", want, j, err)
		}
	}
	if _, err := r.ClaimNext(ctx); !errors.Is(err, job.ErrNoPendingJob) {
		t.Fatalf("ожидали ErrNoPendingJob, получили %v", err)
	}
}

// Злодейство: много обработчиков одновременно. Каждый Job должен достаться ровно одному.
func TestClaimNextConcurrent(t *testing.T) {
	r := memory.New()
	const jobs, workers = 200, 16
	for i := 0; i < jobs; i++ {
		create(t, r, fmt.Sprintf("job-%03d", i))
	}
	var (
		mu  sync.Mutex
		got = map[string]int{}
		wg  sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, err := r.ClaimNext(ctx)
				if errors.Is(err, job.ErrNoPendingJob) {
					return
				}
				mu.Lock()
				got[j.ID()]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(got) != jobs {
		t.Fatalf("взято %d Job из %d", len(got), jobs)
	}
	for id, n := range got {
		if n != 1 {
			t.Fatalf("%s взят %d раз", id, n)
		}
	}
}
