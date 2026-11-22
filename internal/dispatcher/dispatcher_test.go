package dispatcher_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/dispatcher"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/registry"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

// fakeTool это любой Tool. Dispatcher не знает, что это не OSV, KEV или EPSS.
type fakeTool struct {
	name string
	role tool.Role
	run  func(context.Context, tool.Input) (tool.Result, error)
}

func (f fakeTool) Name() string        { return f.name }
func (f fakeTool) Role() tool.Role     { return f.role }
func (f fakeTool) Description() string { return "fake" }
func (f fakeTool) Run(ctx context.Context, in tool.Input) (tool.Result, error) {
	return f.run(ctx, in)
}

func finder(name string, findings ...vuln.Finding) fakeTool {
	return fakeTool{name: name, role: tool.Finder, run: func(context.Context, tool.Input) (tool.Result, error) {
		return tool.Result{Findings: findings}, nil
	}}
}

func failing(name string, role tool.Role, err error) fakeTool {
	return fakeTool{name: name, role: role, run: func(context.Context, tool.Input) (tool.Result, error) {
		return tool.Result{}, err
	}}
}

// marker это Enricher, который ставит InKEV всем находкам.
func marker(name string) fakeTool {
	return fakeTool{name: name, role: tool.Enricher, run: func(_ context.Context, in tool.Input) (tool.Result, error) {
		for i := range in.Findings {
			in.Findings[i].InKEV = true
		}
		return tool.Result{Findings: in.Findings}, nil
	}}
}

var comps = []vuln.Component{{Name: "lodash", Version: "4.17.20"}}
var found = vuln.Finding{IDs: []string{"GHSA-35jh"}, CVEs: []string{"CVE-2021-23337"}}

// claimed создаёт Job и переводит его в running, как это делает хранилище в ClaimNext.
func claimed(t *testing.T, sources ...string) *job.Job {
	t.Helper()
	j, err := job.New("job-1", sources, comps)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Start(); err != nil {
		t.Fatal(err)
	}
	return j
}

func run(t *testing.T, ctx context.Context, tools ...tool.Tool) *job.Job {
	t.Helper()
	reg, err := registry.New(tools...)
	if err != nil {
		t.Fatal(err)
	}
	j := claimed(t, reg.Names()...)
	if err := dispatcher.New(reg, nil).Run(ctx, j); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return j
}

func TestHappyPath(t *testing.T) {
	j := run(t, context.Background(), finder("a", found), marker("b"))
	s := j.Snapshot()
	if s.Status != job.Done {
		t.Fatalf("ожидали done, получили %s %+v", s.Status, s.Error)
	}
	if len(s.Report.Findings) != 1 || !s.Report.Findings[0].InKEV {
		t.Fatalf("Enricher не применился: %+v", s.Report.Findings)
	}
}

// Новый Tool подключается только регистрацией: имя и логика Dispatcher им неизвестны.
func TestNewToolWithoutDispatcherChange(t *testing.T) {
	j := run(t, context.Background(), finder("brand-new-source", found))
	if j.Status() != job.Done || len(j.Snapshot().Report.Findings) != 1 {
		t.Fatalf("новый Tool не отработал: %s", j.Status())
	}
}

func TestFinderErrorsFailJob(t *testing.T) {
	cases := []struct {
		err  error
		code job.ErrorCode
	}{
		{tool.ErrSourceUnavailable, job.SourceUnavailable},
		{tool.ErrBadResponse, job.BadSourceResponse},
		{errors.New("nil pointer где-то внутри"), job.InternalError},
	}
	for _, c := range cases {
		j := run(t, context.Background(), failing("a", tool.Finder, c.err), marker("b"))
		s := j.Snapshot()
		if s.Status != job.Failed || s.Error.Code != c.code || s.Error.Source != "a" {
			t.Fatalf("%v: получили %s %+v", c.err, s.Status, s.Error)
		}
	}
}

func TestToolPanicFailsJob(t *testing.T) {
	boom := fakeTool{name: "a", role: tool.Finder, run: func(context.Context, tool.Input) (tool.Result, error) {
		panic("Tool упал")
	}}
	s := run(t, context.Background(), boom).Snapshot()
	if s.Status != job.Failed || s.Error.Code != job.InternalError {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}

func TestEnricherUnavailableGivesPartial(t *testing.T) {
	s := run(t, context.Background(), finder("a", found), failing("b", tool.Enricher, tool.ErrSourceUnavailable), marker("c")).Snapshot()
	if s.Status != job.Partial {
		t.Fatalf("ожидали partial, получили %s", s.Status)
	}
	if len(s.Report.MissingSources) != 1 || s.Report.MissingSources[0] != "b" {
		t.Fatalf("MissingSources = %v", s.Report.MissingSources)
	}
	if !s.Report.Findings[0].InKEV {
		t.Fatal("остальные Enricher должны отработать")
	}
}

func TestEnricherLosingFindingsFailsJob(t *testing.T) {
	eater := fakeTool{name: "b", role: tool.Enricher, run: func(context.Context, tool.Input) (tool.Result, error) {
		return tool.Result{}, nil
	}}
	s := run(t, context.Background(), finder("a", found), eater).Snapshot()
	if s.Status != job.Failed || s.Error.Code != job.InternalError {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}

func TestEnricherCannotChangeFinderData(t *testing.T) {
	sneaky := fakeTool{name: "b", role: tool.Enricher, run: func(_ context.Context, in tool.Input) (tool.Result, error) {
		in.Findings[0].IDs[0] = "подмена"
		return tool.Result{}, tool.ErrSourceUnavailable
	}}
	s := run(t, context.Background(), finder("a", found), sneaky).Snapshot()
	if s.Report.Findings[0].IDs[0] != "GHSA-35jh" {
		t.Fatal("Enricher испортил находки, хотя вернул ошибку")
	}
}

// Пользователь отменил Job, пока работал Tool: результат отбрасывается, Job остаётся cancelled.
func TestCancelWhileRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var j *job.Job
	slow := fakeTool{name: "a", role: tool.Finder, run: func(ctx context.Context, _ tool.Input) (tool.Result, error) {
		if err := j.Cancel(); err != nil {
			t.Errorf("Cancel: %v", err)
		}
		cancel()
		<-ctx.Done()
		return tool.Result{}, ctx.Err()
	}}
	reg, _ := registry.New(slow)
	j = claimed(t, "a")
	if err := dispatcher.New(reg, nil).Run(ctx, j); err != nil {
		t.Fatal(err)
	}
	if s := j.Snapshot(); s.Status != job.Cancelled || s.Report != nil {
		t.Fatalf("получили %s, отчёт %v", s.Status, s.Report)
	}
}

// Tool не заметил отмену и вернул результат: он всё равно отбрасывается.
func TestLateResultAfterCancelIsDropped(t *testing.T) {
	var j *job.Job
	stubborn := fakeTool{name: "a", role: tool.Finder, run: func(context.Context, tool.Input) (tool.Result, error) {
		_ = j.Cancel()
		return tool.Result{Findings: []vuln.Finding{found}}, nil
	}}
	reg, _ := registry.New(stubborn)
	j = claimed(t, "a")
	_ = dispatcher.New(reg, nil).Run(context.Background(), j)
	if s := j.Snapshot(); s.Status != job.Cancelled || s.Report != nil {
		t.Fatalf("получили %s, отчёт %v", s.Status, s.Report)
	}
}

// Сервис останавливается, ctx отменён, а пользователь Job не отменял: Job становится failed с кодом interrupted.
func TestShutdownInterruptsJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	slow := fakeTool{name: "a", role: tool.Finder, run: func(ctx context.Context, _ tool.Input) (tool.Result, error) {
		<-ctx.Done()
		return tool.Result{}, context.Canceled
	}}
	s := run(t, ctx, slow).Snapshot()
	if s.Status != job.Failed || s.Error.Code != job.Interrupted {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}

// Dispatcher работает только с Job, который хранилище уже перевело в running.
func TestRunRejectsJobNotRunning(t *testing.T) {
	reg, _ := registry.New(finder("a", found))

	fresh, _ := job.New("job-1", []string{"a"}, comps)
	cancelled, _ := job.New("job-2", []string{"a"}, comps)
	_ = cancelled.Cancel()

	for _, j := range []*job.Job{fresh, cancelled} {
		before := j.Status()
		err := dispatcher.New(reg, nil).Run(context.Background(), j)
		if !errors.Is(err, dispatcher.ErrNotRunning) || j.Status() != before {
			t.Fatalf("%s: получили %v, состояние %s", before, err, j.Status())
		}
	}
}

// Dispatcher проверяет компоненты, сохранённые в Job, а не переданные отдельно.
func TestFinderGetsComponentsFromJob(t *testing.T) {
	var seen []vuln.Component
	spy := fakeTool{name: "a", role: tool.Finder, run: func(_ context.Context, in tool.Input) (tool.Result, error) {
		seen = in.Components
		return tool.Result{}, nil
	}}
	run(t, context.Background(), spy)
	if len(seen) != 1 || seen[0] != comps[0] {
		t.Fatalf("Finder получил %v", seen)
	}
}

func TestUnknownToolInJobFailsJob(t *testing.T) {
	reg, _ := registry.New(finder("a", found))
	j := claimed(t, "a", "ghost")
	_ = dispatcher.New(reg, nil).Run(context.Background(), j)
	if s := j.Snapshot(); s.Status != job.Failed || s.Error.Code != job.InternalError {
		t.Fatalf("получили %s %+v", s.Status, s.Error)
	}
}
