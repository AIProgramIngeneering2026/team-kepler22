package job_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

var comps = []vuln.Component{{Name: "log4j-core", Version: "2.14.1"}}

var allStatuses = []job.Status{job.Created, job.Running, job.Done, job.Partial, job.Failed, job.Cancelled}

func newJob(t *testing.T) *job.Job {
	t.Helper()
	j, err := job.New("job-1", []string{"osv", "kev"}, comps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return j
}

// jobIn доводит Job до нужного состояния разрешёнными переходами.
func jobIn(t *testing.T, s job.Status) *job.Job {
	t.Helper()
	j := newJob(t)
	step := func(err error) {
		if err != nil {
			t.Fatalf("подготовка состояния %s: %v", s, err)
		}
	}
	switch s {
	case job.Created:
	case job.Cancelled:
		step(j.Cancel())
	default:
		step(j.Start())
		switch s {
		case job.Done:
			step(j.Finish(job.Report{}))
		case job.Partial:
			step(j.Finish(job.Report{MissingSources: []string{"kev"}}))
		case job.Failed:
			step(j.Fail(job.Error{Code: job.SourceUnavailable, Source: "osv"}))
		}
	}
	if j.Status() != s {
		t.Fatalf("ожидали %s, получили %s", s, j.Status())
	}
	return j
}

// try вызывает метод Job, который ведёт в состояние to.
func try(j *job.Job, to job.Status) error {
	switch to {
	case job.Running:
		return j.Start()
	case job.Done:
		return j.Finish(job.Report{})
	case job.Partial:
		return j.Finish(job.Report{MissingSources: []string{"kev"}})
	case job.Failed:
		return j.Fail(job.Error{Code: job.InternalError})
	case job.Cancelled:
		return j.Cancel()
	}
	panic("в created перейти нельзя: такого метода нет")
}

func expectRejected(t *testing.T, j *job.Job, err error, keep job.Status) {
	t.Helper()
	if !errors.Is(err, job.ErrInvalidTransition) {
		t.Fatalf("ожидали ErrInvalidTransition, получили %v", err)
	}
	var te *job.TransitionError
	if !errors.As(err, &te) || te.From != keep {
		t.Fatalf("в ошибке нет исходного состояния %s: %v", keep, err)
	}
	if j.Status() != keep {
		t.Fatalf("состояние изменилось: было %s, стало %s", keep, j.Status())
	}
}

func TestHappyPath(t *testing.T) {
	j := newJob(t)
	if j.Status() != job.Created {
		t.Fatalf("новый Job должен быть created, а он %s", j.Status())
	}
	if err := j.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	f := vuln.Finding{IDs: []string{"CVE-2023-39325"}, CVEs: []string{"CVE-2023-39325"}}
	if err := j.Finish(job.Report{Findings: []vuln.Finding{f}}); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	s := j.Snapshot()
	if s.Status != job.Done || s.Report == nil || len(s.Report.Findings) != 1 || s.Error != nil {
		t.Fatalf("неверный итог: %+v", s)
	}
}

func TestFinishWithMissingSourceIsPartial(t *testing.T) {
	j := jobIn(t, job.Running)
	if err := j.Finish(job.Report{MissingSources: []string{"epss"}}); err != nil {
		t.Fatal(err)
	}
	if j.Status() != job.Partial {
		t.Fatalf("ожидали partial, получили %s", j.Status())
	}
}

// Все пары состояний: разрешено ровно то, что есть на диаграмме, остальное отклоняется.
func TestAllTransitions(t *testing.T) {
	for _, from := range allStatuses {
		for _, to := range allStatuses {
			if to == job.Created {
				continue // метода «вернуть в created» нет вовсе
			}
			t.Run(string(from)+"→"+string(to), func(t *testing.T) {
				j := jobIn(t, from)
				err := try(j, to)
				if job.CanTransition(from, to) {
					if err != nil || j.Status() != to {
						t.Fatalf("разрешённый переход не прошёл: %v", err)
					}
					return
				}
				expectRejected(t, j, err, from)
			})
		}
	}
}

// Злодейство: отменить уже завершённый Job.
func TestAttackCancelTerminal(t *testing.T) {
	for _, from := range []job.Status{job.Done, job.Partial, job.Failed, job.Cancelled} {
		j := jobIn(t, from)
		expectRejected(t, j, j.Cancel(), from)
	}
}

// Злодейство: завершить Job дважды и переписать отчёт.
func TestAttackFinishTwice(t *testing.T) {
	j := jobIn(t, job.Running)
	first := job.Report{Findings: []vuln.Finding{{IDs: []string{"A"}}}}
	if err := j.Finish(first); err != nil {
		t.Fatal(err)
	}
	second := job.Report{Findings: []vuln.Finding{{IDs: []string{"B"}}}}
	expectRejected(t, j, j.Finish(second), job.Done)
	expectRejected(t, j, j.Fail(job.Error{Code: job.InternalError}), job.Done)
	if got := j.Snapshot().Report.Findings[0].IDs[0]; got != "A" {
		t.Fatalf("отчёт переписан: %s", got)
	}
}

// Злодейство: поменять состояние в обход методов, через копию или через хранилище.
func TestAttackTamperSnapshot(t *testing.T) {
	j := jobIn(t, job.Running)
	s := j.Snapshot()
	s.Status = job.Done
	if j.Status() != job.Running {
		t.Fatal("изменение копии поменяло Job")
	}

	cases := map[string]job.Snapshot{
		"неизвестное состояние": {ID: "x", Sources: []string{"osv"}, Components: comps, Status: "hacked"},
		"done без отчёта":       {ID: "x", Sources: []string{"osv"}, Components: comps, Status: job.Done},
		"failed без ошибки":     {ID: "x", Sources: []string{"osv"}, Components: comps, Status: job.Failed},
		"partial без пропусков": {ID: "x", Sources: []string{"osv"}, Components: comps, Status: job.Partial, Report: &job.Report{}},
		"running с отчётом":     {ID: "x", Sources: []string{"osv"}, Components: comps, Status: job.Running, Report: &job.Report{}},
		"failed с чужим кодом":  {ID: "x", Sources: []string{"osv"}, Components: comps, Status: job.Failed, Error: &job.Error{Code: "oops"}},
		"пустой id":             {Sources: []string{"osv"}, Components: comps, Status: job.Created},
		"без компонентов":       {ID: "x", Sources: []string{"osv"}, Status: job.Created},
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := job.Restore(snap); !errors.Is(err, job.ErrInvalidJob) {
				t.Fatalf("ожидали ErrInvalidJob, получили %v", err)
			}
		})
	}
}

// Злодейство: отмена и завершение приходят одновременно. Выиграть должен ровно один.
func TestAttackRaceFinishAndCancel(t *testing.T) {
	for i := 0; i < 100; i++ {
		j := jobIn(t, job.Running)
		var wg sync.WaitGroup
		results := make(chan error, 20)
		for k := 0; k < 20; k++ {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				if k%2 == 0 {
					results <- j.Cancel()
				} else {
					results <- j.Finish(job.Report{})
				}
			}(k)
		}
		wg.Wait()
		close(results)
		ok := 0
		for err := range results {
			if err == nil {
				ok++
			} else if !errors.Is(err, job.ErrInvalidTransition) {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
		}
		if ok != 1 || !j.Status().Terminal() {
			t.Fatalf("успешных переходов %d, состояние %s", ok, j.Status())
		}
	}
}

func TestFailNeedsKnownCode(t *testing.T) {
	j := jobIn(t, job.Running)
	if err := j.Fail(job.Error{Code: "whatever"}); !errors.Is(err, job.ErrInvalidJob) {
		t.Fatalf("ожидали ErrInvalidJob, получили %v", err)
	}
	if j.Status() != job.Running {
		t.Fatalf("состояние изменилось: %s", j.Status())
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := job.New("", []string{"osv"}, comps); !errors.Is(err, job.ErrInvalidJob) {
		t.Fatalf("пустой id: %v", err)
	}
	if _, err := job.New("id", nil, comps); !errors.Is(err, job.ErrInvalidJob) {
		t.Fatalf("без источников: %v", err)
	}
	if _, err := job.New("id", []string{"osv"}, nil); !errors.Is(err, job.ErrInvalidJob) {
		t.Fatalf("без компонентов: %v", err)
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	for _, s := range allStatuses {
		orig := jobIn(t, s)
		got, err := job.Restore(orig.Snapshot())
		if err != nil || got.Status() != s || len(got.Components()) != len(comps) {
			t.Fatalf("%s: %v", s, err)
		}
	}
}
