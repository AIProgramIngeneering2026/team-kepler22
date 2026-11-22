// Package osv это Tool-Finder: ищет уязвимости компонентов в OSV.dev.
package osv

import (
	"context"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

// Client это порт к OSV.dev. HTTP-адаптер с таймаутом и повторами появится позже,
// в тестах его заменяет подделка. Адаптер возвращает tool.ErrSourceUnavailable или tool.ErrBadResponse.
type Client interface {
	Query(ctx context.Context, components []vuln.Component) ([]vuln.Finding, error)
}

// Source реализует tool.Tool.
type Source struct{ client Client }

var _ tool.Tool = (*Source)(nil)

// New создаёт Tool поверх клиента.
func New(c Client) *Source { return &Source{client: c} }

func (*Source) Name() string    { return "osv" }
func (*Source) Role() tool.Role { return tool.Finder }
func (*Source) Description() string {
	return "Ищет известные уязвимости и вредоносные пакеты по компонентам SBOM в базе OSV.dev."
}

// Run проверяет компоненты с версией. Компоненты без версии попадают в Skipped.
func (s *Source) Run(ctx context.Context, in tool.Input) (tool.Result, error) {
	var res tool.Result
	var query []vuln.Component
	for _, c := range in.Components {
		if c.Version == "" {
			res.Skipped = append(res.Skipped, vuln.Skipped{Component: c, Reason: vuln.NoVersion})
			continue
		}
		query = append(query, c)
	}
	if len(query) == 0 {
		return res, nil
	}
	if err := ctx.Err(); err != nil {
		return tool.Result{}, err
	}
	found, err := s.client.Query(ctx, query)
	if err != nil {
		return tool.Result{}, err
	}
	res.Findings = found
	return res, nil
}
