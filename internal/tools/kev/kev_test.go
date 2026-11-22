package kev_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tools/kev"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

type fakeClient struct {
	cat kev.Catalog
	err error
}

func (f fakeClient) Catalog(context.Context) (kev.Catalog, error) { return f.cat, f.err }

func TestMarksFindingsFromCatalog(t *testing.T) {
	date := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	c := fakeClient{cat: kev.Catalog{CVEs: map[string]bool{"CVE-2021-44228": true}, DataDate: &date}}
	in := []vuln.Finding{
		{IDs: []string{"GHSA-jfh8"}, CVEs: []string{"CVE-2021-44228"}},
		{IDs: []string{"GHSA-x"}, CVEs: []string{"CVE-2020-0001"}},
		{IDs: []string{"MAL-2024-1"}},
	}
	res, err := kev.New(c).Run(context.Background(), tool.Input{Findings: in})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Findings[0].InKEV || res.Findings[1].InKEV || res.Findings[2].InKEV {
		t.Fatalf("InKEV расставлен неверно: %+v", res.Findings)
	}
	if res.DataDate == nil || !res.DataDate.Equal(date) {
		t.Fatalf("DataDate = %v", res.DataDate)
	}
	if in[0].InKEV {
		t.Fatal("Tool изменил входные данные")
	}
}

func TestPassesSourceErrors(t *testing.T) {
	_, err := kev.New(fakeClient{err: tool.ErrSourceUnavailable}).Run(context.Background(),
		tool.Input{Findings: []vuln.Finding{{CVEs: []string{"CVE-1"}}}})
	if !errors.Is(err, tool.ErrSourceUnavailable) {
		t.Fatalf("получили %v", err)
	}
}
