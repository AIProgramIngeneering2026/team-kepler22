// Package epss это Tool-Enricher: добавляет вероятность эксплуатации из FIRST EPSS.
package epss

import (
	"context"
	"sort"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

// Client это порт к FIRST EPSS. Деление на пачки по 100 CVE и повторы живут в адаптере.
type Client interface {
	Scores(ctx context.Context, cves []string) (map[string]float64, error)
}

// Source реализует tool.Tool.
type Source struct{ client Client }

var _ tool.Tool = (*Source)(nil)

// New создаёт Tool поверх клиента.
func New(c Client) *Source { return &Source{client: c} }

func (*Source) Name() string    { return "epss" }
func (*Source) Role() tool.Role { return tool.Enricher }
func (*Source) Description() string {
	return "Добавляет вероятность эксплуатации уязвимости в ближайшие 30 дней по данным FIRST EPSS."
}

// Run возвращает те же находки с полем EPSS. У находки с несколькими CVE берётся наибольшая оценка.
// Находки без CVE и CVE без оценки остаются с EPSS = nil.
func (s *Source) Run(ctx context.Context, in tool.Input) (tool.Result, error) {
	out := vuln.CloneAll(in.Findings)
	set := map[string]bool{}
	for _, f := range out {
		for _, c := range f.CVEs {
			set[c] = true
		}
	}
	if len(set) == 0 {
		return tool.Result{Findings: out}, nil
	}
	cves := make([]string, 0, len(set))
	for c := range set {
		cves = append(cves, c)
	}
	sort.Strings(cves)
	scores, err := s.client.Scores(ctx, cves)
	if err != nil {
		return tool.Result{}, err
	}
	for i := range out {
		for _, c := range out[i].CVEs {
			v, ok := scores[c]
			if !ok || v < 0 || v > 1 {
				continue
			}
			if out[i].EPSS == nil || v > *out[i].EPSS {
				score := v
				out[i].EPSS = &score
			}
		}
	}
	return tool.Result{Findings: out}, nil
}
