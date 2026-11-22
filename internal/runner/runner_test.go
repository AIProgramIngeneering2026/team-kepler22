package runner_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/dispatcher"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/registry"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/runner"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/storage/memory"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

var (
	ctx   = context.Background()
	comps = []vuln.Component{{Name: "lodash", Version: "4.17.20"}}
)

// finder это Tool-Finder; run задаёт его поведение.
type finder struct {
	run func(context.Context) error
}

func (finder) Name() string        { return "finder" }
func (finder) Role() tool.Role     { return tool.Finder }
func (finder) Description() string { return "fake" }
func (f finder) Run(ctx context.Context, _ tool.Input) (tool.Result, error) {
	if f.run != nil {
		if err := f.run(ctx); err != nil {
			return tool.Result{}, err
		}
	}
	return tool.Result{}, nil
}

// blocking висит, пока не закрыт release или не отменён ctx.
func blocking(release <-chan struct{}) finder {
	return finder{run: func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
}

func newRunner(t *testing.T, repo job.Repository, f finder) *runner.Runner {
	t.Helper()
	reg, err := registry.New(f)
	if err != nil {
		t.Fatal(err)
	}
	return runner.New(repo, dispatcher.New(reg, nil), nil)
}

// start запускает обработчики; stop останавливает их и ждёт выхода, как при остановке сервиса.
func start(t *testing.T, r *runner.Runner, workers int) (stop func()) {
	t.Helper()
	runCtx, cancel := context.WithCancel(ctx)
	r.Start(runCtx, workers)
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); r.Wait() }) }
	t.Cleanup(stop)
	return stop
}

func create(t *testing.T, repo job.Repository, id string) {
	t.Helper()
	j, err := job.New(id, []string{"finder"}, comps)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, j); err != nil {
		t.Fatal(err)
	}
}

func stored(t *testing.T, repo job.Repository, id string) job.Snapshot {
	t.Helper()
	j, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return j.Snapshot()
}

func waitStatus(t *testing.T, repo job.Repository, id string, want job.Status) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for stored(t, repo, id).Status != want {
		if time.Now().After(deadline) {
			t.Fatalf("Job %s в состоянии %s, ждали %s", id, stored(t, repo, id).Status, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// Job, созданный до запуска обработчиков (например, до перезапуска), выполняется.
func TestRunsJobCreatedBeforeStart(t *testing.T) {
	repo := memory.New()
	create(t, repo, "job-1")
	r := newRunner(t, repo, finder{})
	if err := r.RecoverInterrupted(ctx); err != nil {
		t.Fatal(err)
	}
	start(t, r, 1)
	waitStatus(t, repo, "job-1", job.Done)
}

func TestWorkersLimitParallelism(t *testing.T) {
	const workers, jobs = 2, 6
	var now, peak atomic.Int32
	started := make(chan struct{}, jobs)
	release := make(chan struct{})
	f := finder{run: func(context.Context) error {
		n := now.Add(1)
		defer now.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		started <- struct{}{}
		<-release
		return nil
	}}
	repo := memory.New()
	for i := 0; i < jobs; i++ {
		create(t, repo, fmt.Sprintf("job-%d", i))
	}
	start(t, newRunner(t, repo, f), workers)

	for i := 0; i < workers; i++ {
		<-started // оба обработчика заняты и ждут release
	}
	close(release)
	for i := 0; i < jobs; i++ {
		waitStatus(t, repo, fmt.Sprintf("job-%d", i), job.Done)
	}
	if p := peak.Load(); p != workers {
		t.Fatalf("одновременно работало %d Job при %d обработчиках", p, workers)
	}
}

func TestShutdownInterruptsRunningJob(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	repo := memory.New()
	create(t, repo, "job-1")
	stop := start(t, newRunner(t, repo, blocking(release)), 1)
	waitStatus(t, repo, "job-1", job.Running)
	stop()
	if s := stored(t, repo, "job-1"); s.Status != job.Failed || s.Error.Code != job.Interrupted {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}

// З2. Вечная работа: сервер перезапустился, Job не должен остаться в running.
func TestZ2RestartDoesNotLeaveJobRunning(t *testing.T) {
	repo := memory.New()
	create(t, repo, "left-running")
	if _, err := repo.ClaimNext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := newRunner(t, repo, finder{}).RecoverInterrupted(ctx); err != nil {
		t.Fatal(err)
	}
	if s := stored(t, repo, "left-running"); s.Status != job.Failed || s.Error.Code != job.Interrupted {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}

func TestCancelRunning(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	repo := memory.New()
	create(t, repo, "job-1")
	r := newRunner(t, repo, blocking(release))
	stop := start(t, r, 1)
	waitStatus(t, repo, "job-1", job.Running)

	j, ok, err := r.CancelRunning(ctx, "job-1")
	if err != nil || !ok || j.Status() != job.Cancelled {
		t.Fatalf("CancelRunning: ok=%v err=%v", ok, err)
	}
	stop() // обработчик закончил и не перезаписал отмену
	if s := stored(t, repo, "job-1"); s.Status != job.Cancelled || s.Error != nil {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}

func TestCancelRunningUnknownToThisProcess(t *testing.T) {
	repo := memory.New()
	create(t, repo, "job-1")
	_, ok, err := newRunner(t, repo, finder{}).CancelRunning(ctx, "job-1")
	if ok || err != nil {
		t.Fatalf("ожидали ok=false без ошибки, получили ok=%v err=%v", ok, err)
	}
}
