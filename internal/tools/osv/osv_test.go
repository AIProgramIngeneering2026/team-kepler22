package osv_test

import (
	"context"
	"errors"
	"testing"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tools/osv"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

type fakeClient struct {
	got []vuln.Component
	res []vuln.Finding
	err error
}

func (f *fakeClient) Query(_ context.Context, c []vuln.Component) ([]vuln.Finding, error) {
	f.got = c
	return f.res, f.err
}

func TestSkipsComponentsWithoutVersion(t *testing.T) {
	c := &fakeClient{res: []vuln.Finding{{IDs: []string{"GHSA-1"}}}}
	res, err := osv.New(c).Run(context.Background(), tool.Input{Components: []vuln.Component{
		{Name: "lodash", Version: "4.17.20"},
		{Name: "left-pad"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.got) != 1 || c.got[0].Name != "lodash" {
		t.Fatalf("в OSV ушли не те компоненты: %+v", c.got)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Reason != vuln.NoVersion {
		t.Fatalf("Skipped = %+v", res.Skipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %+v", res.Findings)
	}
}

func TestPassesSourceErrors(t *testing.T) {
	for _, want := range []error{tool.ErrSourceUnavailable, tool.ErrBadResponse} {
		_, err := osv.New(&fakeClient{err: want}).Run(context.Background(),
			tool.Input{Components: []vuln.Component{{Name: "a", Version: "1"}}})
		if !errors.Is(err, want) {
			t.Fatalf("ожидали %v, получили %v", want, err)
		}
	}
}

func TestStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := osv.New(&fakeClient{}).Run(ctx, tool.Input{Components: []vuln.Component{{Name: "a", Version: "1"}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидали context.Canceled, получили %v", err)
	}
}
