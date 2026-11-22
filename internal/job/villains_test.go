package job_test

import (
	"testing"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/job"
)

// Злодейства З1–З6 с пары «Взлом Job». З2 (перезапуск) проверяется в runner: TestZ2RestartDoesNotLeaveJobRunning.

// З1. Двойная работа: create, start, start — второй start отклонён.
func TestZ1DoubleWork(t *testing.T) {
	j := jobIn(t, job.Running)
	expectRejected(t, j, j.Start(), job.Running)
}

// З3. Отменённое стало готовым: create, start, cancel, finish — finish от Tool отклонён.
func TestZ3CancelledBecomesDone(t *testing.T) {
	j := jobIn(t, job.Running)
	if err := j.Cancel(); err != nil {
		t.Fatal(err)
	}
	expectRejected(t, j, j.Finish(job.Report{}), job.Cancelled)
	expectRejected(t, j, j.Finish(job.Report{MissingSources: []string{"kev"}}), job.Cancelled)
}

// З4. Два итога: create, start, fail, finish — второй итог отклонён.
func TestZ4FailedBecomesDone(t *testing.T) {
	j := jobIn(t, job.Failed)
	expectRejected(t, j, j.Finish(job.Report{}), job.Failed)
	if j.Snapshot().Report != nil {
		t.Fatal("у failed появился отчёт")
	}
}

// З5. Успех без работы: create, finish — любой итог в обход running отклонён.
func TestZ5DoneWithoutWork(t *testing.T) {
	for _, to := range []job.Status{job.Done, job.Partial, job.Failed} {
		j := newJob(t)
		expectRejected(t, j, try(j, to), job.Created)
	}
}

// З6. Повтор успешного: done, start — конечный Job снова в работу не идёт.
// Повторная проверка в нашей системе — только новый Job через POST /jobs.
func TestZ6DoneRunsAgain(t *testing.T) {
	for _, from := range []job.Status{job.Done, job.Partial, job.Failed, job.Cancelled} {
		j := jobIn(t, from)
		expectRejected(t, j, j.Start(), from)
	}
}
