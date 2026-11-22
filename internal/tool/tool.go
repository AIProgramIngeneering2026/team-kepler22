// Package tool задаёт контракт источника данных об уязвимостях (docs/tool-contract.md).
package tool

import (
	"context"
	"errors"
	"time"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/vuln"
)

// Role определяет, когда Dispatcher запускает Tool: сначала все Finder, потом все Enricher.
type Role int

const (
	Finder   Role = iota // находит уязвимости по компонентам SBOM
	Enricher             // дополняет уже найденные уязвимости
)

func (r Role) String() string {
	if r == Finder {
		return "finder"
	}
	return "enricher"
}

// Tool это один источник данных. Dispatcher знает Tool только через этот интерфейс.
type Tool interface {
	// Name уникальное имя, по нему клиент выбирает источник в поле sources.
	Name() string
	Role() Role
	// Description понадобится LLM во втором семестре, чтобы выбирать Tool.
	Description() string
	// Run выполняет работу. Обязан прерваться, когда отменён ctx.
	Run(ctx context.Context, in Input) (Result, error)
}

// Input это входные данные Tool.
type Input struct {
	Components []vuln.Component // для Finder
	Findings   []vuln.Finding   // для Enricher
}

// Result это ответ Tool.
type Result struct {
	Findings []vuln.Finding // Finder: новые находки; Enricher: те же находки с заполненными полями
	Skipped  []vuln.Skipped
	DataDate *time.Time // дата данных, если они взяты из кэша
}

var (
	// ErrSourceUnavailable: источник не ответил после всех повторов.
	ErrSourceUnavailable = errors.New("source_unavailable")
	// ErrBadResponse: ответ источника нельзя разобрать.
	ErrBadResponse = errors.New("bad_source_response")
)
