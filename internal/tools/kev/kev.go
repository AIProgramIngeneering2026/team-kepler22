// Package kev это Tool-Enricher: отмечает уязвимости из каталога CISA KEV.
package kev

import (
	"context"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

// Catalog это каталог KEV: набор CVE и дата данных, если каталог взят из кэша.
type Catalog struct {
	CVEs     map[string]bool
	DataDate *time.Time
}

// Client это порт к каталогу CISA KEV. Кэш и повторы живут в адаптере.
type Client interface {
	Catalog(ctx context.Context) (Catalog, error)
}

// Source реализует tool.Tool.
type Source struct{ client Client }

var _ tool.Tool = (*Source)(nil)

// New создаёт Tool поверх клиента.
func New(c Client) *Source { return &Source{client: c} }

func (*Source) Name() string    { return "kev" }
func (*Source) Role() tool.Role { return tool.Enricher }
func (*Source) Description() string {
	return "Отмечает уязвимости, которые уже используют в реальных атаках, по каталогу CISA KEV."
}

// Run возвращает те же находки, у которых заполнено поле InKEV.
func (s *Source) Run(ctx context.Context, in tool.Input) (tool.Result, error) {
	out := vuln.CloneAll(in.Findings)
	if len(out) == 0 {
		return tool.Result{Findings: out}, nil
	}
	cat, err := s.client.Catalog(ctx)
	if err != nil {
		return tool.Result{}, err
	}
	for i := range out {
		for _, cve := range out[i].CVEs {
			if cat.CVEs[cve] {
				out[i].InKEV = true
				break
			}
		}
	}
	return tool.Result{Findings: out, DataDate: cat.DataDate}, nil
}
