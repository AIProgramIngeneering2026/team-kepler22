package epss_test

import (
	"context"
	"errors"
	"testing"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tools/epss"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

type fakeClient struct {
	scores map[string]float64
	err    error
	asked  []string
}

func (f *fakeClient) Scores(_ context.Context, cves []string) (map[string]float64, error) {
	f.asked = cves
	return f.scores, f.err
}

func TestTakesMaxScoreAndSkipsGarbage(t *testing.T) {
	c := &fakeClient{scores: map[string]float64{"CVE-1": 0.02, "CVE-2": 0.4, "CVE-3": 7}}
	res, err := epss.New(c).Run(context.Background(), tool.Input{Findings: []vuln.Finding{
		{CVEs: []string{"CVE-1", "CVE-2"}},
		{CVEs: []string{"CVE-3"}},
		{IDs: []string{"MAL-1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if e := res.Findings[0].EPSS; e == nil || *e != 0.4 {
		t.Fatalf("ожидали 0.4, получили %v", e)
	}
	if res.Findings[1].EPSS != nil {
		t.Fatal("оценка вне диапазона 0..1 должна отбрасываться")
	}
	if res.Findings[2].EPSS != nil {
		t.Fatal("у находки без CVE оценки быть не может")
	}
	if len(c.asked) != 3 {
		t.Fatalf("запрошены CVE %v", c.asked)
	}
}

func TestNoCVEsNoRequest(t *testing.T) {
	c := &fakeClient{err: errors.New("не должен вызываться")}
	if _, err := epss.New(c).Run(context.Background(), tool.Input{Findings: []vuln.Finding{{IDs: []string{"MAL-1"}}}}); err != nil {
		t.Fatal(err)
	}
}

func TestPassesSourceErrors(t *testing.T) {
	_, err := epss.New(&fakeClient{err: tool.ErrBadResponse}).Run(context.Background(),
		tool.Input{Findings: []vuln.Finding{{CVEs: []string{"CVE-1"}}}})
	if !errors.Is(err, tool.ErrBadResponse) {
		t.Fatalf("получили %v", err)
	}
}
