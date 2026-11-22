package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/dispatcher"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/registry"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/runner"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/service"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/storage/memory"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tools/epss"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tools/kev"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tools/osv"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

// Подделки адаптеров: настоящие HTTP-клиенты появятся на следующих практиках.
type osvFake struct {
	block chan struct{} // если задан, запрос висит, пока канал не закрыт или ctx не отменён
}

func (f osvFake) Query(ctx context.Context, _ []vuln.Component) ([]vuln.Finding, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []vuln.Finding{{IDs: []string{"GHSA-jfh8", "CVE-2021-44228"}, CVEs: []string{"CVE-2021-44228"}}}, nil
}

type kevFake struct{}

func (kevFake) Catalog(context.Context) (kev.Catalog, error) {
	return kev.Catalog{CVEs: map[string]bool{"CVE-2021-44228": true}}, nil
}

type epssFake struct{}

func (epssFake) Scores(context.Context, []string) (map[string]float64, error) {
	return map[string]float64{"CVE-2021-44228": 0.94}, nil
}

var (
	ctx  = context.Background()
	sbom = []vuln.Component{{Name: "log4j-core", Version: "2.14.1", Ecosystem: "Maven"}}
)

// app собирает систему так же, как это будет делать main.
type app struct {
	repo *memory.Repository
	run  *runner.Runner
	svc  *service.Service
}

func newApp(t *testing.T, o osvFake) app {
	t.Helper()
	reg, err := registry.New(osv.New(o), kev.New(kevFake{}), epss.New(epssFake{}))
	if err != nil {
		t.Fatal(err)
	}
	repo := memory.New()
	run := runner.New(repo, dispatcher.New(reg, nil), nil)
	return app{repo: repo, run: run, svc: service.New(repo, reg, run)}
}

// start запускает обработчики; stop останавливает их и ждёт выхода, как при остановке сервиса.
func (a app) start(t *testing.T) (stop func()) {
	t.Helper()
	runCtx, cancel := context.WithCancel(ctx)
	a.run.Start(runCtx, 1)
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); a.run.Wait() }) }
	t.Cleanup(stop)
	return stop
}

func (a app) submit(t *testing.T) string {
	t.Helper()
	j, err := a.svc.Submit(ctx, service.Request{Components: sbom})
	if err != nil {
		t.Fatal(err)
	}
	return j.ID()
}

// stored читает Job так же, как GET /jobs/{id}.
func (a app) stored(t *testing.T, id string) job.Snapshot {
	t.Helper()
	j, err := a.svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return j.Snapshot()
}

func (a app) waitStatus(t *testing.T, id string, want job.Status) job.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := a.stored(t, id)
		if s.Status == want {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("Job %s в состоянии %s, ждали %s", id, s.Status, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHappyPathEndToEnd(t *testing.T) {
	a := newApp(t, osvFake{})
	a.start(t)
	s := a.waitStatus(t, a.submit(t), job.Done)
	f := s.Report.Findings[0]
	if !f.InKEV || f.EPSS == nil || *f.EPSS != 0.94 {
		t.Fatalf("находка не обогащена: %+v", f)
	}
}

func TestSubmitOnlySavesJob(t *testing.T) {
	a := newApp(t, osvFake{})
	if got := a.stored(t, a.submit(t)).Status; got != job.Created {
		t.Fatalf("Submit должен только сохранить Job, а он %s", got)
	}
}

func expectProblem(t *testing.T, err error, code error, p service.Problem, field string) {
	t.Helper()
	var re *service.RequestError
	if !errors.Is(err, code) || !errors.As(err, &re) || re.Problem != p || re.Field != field {
		t.Fatalf("ожидали %v %s в поле %s, получили %v", code, p, field, err)
	}
}

func TestUnknownSource(t *testing.T) {
	_, err := newApp(t, osvFake{}).svc.Submit(ctx, service.Request{Components: sbom, Sources: []string{"osv", "nvd"}})
	expectProblem(t, err, registry.ErrUnknownTool, service.UnknownSource, "sources[1]")
}

func TestInvalidParams(t *testing.T) {
	many := make([]vuln.Component, service.MaxComponents+1)
	for i := range many {
		many[i] = vuln.Component{Name: "x", Version: "1"}
	}
	cases := []struct {
		name    string
		req     service.Request
		problem service.Problem
		field   string
	}{
		{"пустой SBOM", service.Request{}, service.NoComponents, "components"},
		{"слишком много компонентов", service.Request{Components: many}, service.TooManyComponents, "components"},
		{"компонент без имени", service.Request{Components: append(sbom, vuln.Component{Version: "1"})}, service.ComponentWithoutName, "components[1].name"},
		{"пустой список источников", service.Request{Components: sbom, Sources: []string{}}, service.NoSources, "sources"},
		{"источник дважды", service.Request{Components: sbom, Sources: []string{"osv", "osv"}}, service.DuplicateSource, "sources[1]"},
		{"нет источника-Finder", service.Request{Components: sbom, Sources: []string{"kev", "epss"}}, service.NoFinder, "sources"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newApp(t, osvFake{}).svc.Submit(ctx, c.req)
			expectProblem(t, err, service.ErrInvalidParams, c.problem, c.field)
		})
	}
}

// Отменённый Job из очереди обработчик пропускает: следующий Job выполняется, отменённый нет.
func TestCancelCreatedJob(t *testing.T) {
	a := newApp(t, osvFake{})
	cancelled := a.submit(t)
	if _, err := a.svc.Cancel(ctx, cancelled); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	next := a.submit(t)
	a.start(t)
	a.waitStatus(t, next, job.Done)
	if s := a.stored(t, cancelled); s.Status != job.Cancelled || s.Report != nil {
		t.Fatalf("получили %s, отчёт %v", s.Status, s.Report)
	}
}

// Регрессия: хранилище отдаёт копии, как PostgreSQL, и обработчик не должен перезаписать отмену.
func TestCancelRunningJob(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	a := newApp(t, osvFake{block: block})
	stop := a.start(t)
	id := a.submit(t)
	a.waitStatus(t, id, job.Running)
	if j, err := a.svc.Cancel(ctx, id); err != nil || j.Status() != job.Cancelled {
		t.Fatalf("Cancel: %v", err)
	}
	stop()
	if s := a.stored(t, id); s.Status != job.Cancelled || s.Report != nil || s.Error != nil {
		t.Fatalf("получили %s, отчёт %v, ошибка %+v", s.Status, s.Report, s.Error)
	}
}

// Job выполняет другой процесс: отмена записывается, его результат её не перезапишет.
func TestCancelJobRunningElsewhere(t *testing.T) {
	a := newApp(t, osvFake{})
	id := a.submit(t)
	elsewhere, err := a.repo.ClaimNext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.svc.Cancel(ctx, id); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	_ = elsewhere.Finish(job.Report{})
	if err := a.repo.Update(ctx, elsewhere, job.Running); !errors.Is(err, job.ErrConflict) {
		t.Fatalf("чужой обработчик перезаписал отмену: %v", err)
	}
	if got := a.stored(t, id).Status; got != job.Cancelled {
		t.Fatalf("ожидали cancelled, получили %s", got)
	}
}

func TestCancelFinishedJobRejected(t *testing.T) {
	a := newApp(t, osvFake{})
	a.start(t)
	id := a.submit(t)
	a.waitStatus(t, id, job.Done)
	if _, err := a.svc.Cancel(ctx, id); !errors.Is(err, job.ErrInvalidTransition) {
		t.Fatalf("ожидали ErrInvalidTransition, получили %v", err)
	}
	if got := a.stored(t, id).Status; got != job.Done {
		t.Fatalf("состояние изменилось: %s", got)
	}
}

func TestCancelUnknownJob(t *testing.T) {
	if _, err := newApp(t, osvFake{}).svc.Cancel(ctx, "nope"); !errors.Is(err, job.ErrNotFound) {
		t.Fatalf("получили %v", err)
	}
}
