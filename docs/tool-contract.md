# Контракт Tool

Tool это один источник данных об уязвимостях. Dispatcher знает Tool только через этот интерфейс и берёт их из Registry, поэтому новый источник добавляется регистрацией без правки Dispatcher.

## Интерфейс

```go
package tool

type Role int

const (
	Finder   Role = iota // находит уязвимости по компонентам SBOM
	Enricher             // дополняет уже найденные уязвимости
)

type Tool interface {
	// Name уникальное имя, по нему клиент выбирает источник в поле sources.
	Name() string
	// Role определяет, когда Dispatcher запускает Tool: сначала все Finder, потом все Enricher.
	Role() Role
	// Description понадобится LLM во втором семестре, чтобы выбирать Tool.
	Description() string
	// Run выполняет работу. Обязан прерваться, когда отменён ctx.
	Run(ctx context.Context, in Input) (Result, error)
}

type Input struct {
	Components []Component // для Finder: компоненты SBOM с именем, версией и purl
	Findings   []Finding   // для Enricher: находки, которые нашли Finder
}

type Result struct {
	Findings []Finding  // Finder: новые находки; Enricher: те же находки с заполненными полями
	Skipped  []Skipped  // компоненты, которые Tool не смог проверить, с причиной
	DataDate *time.Time // дата данных, если они взяты из кэша
}
```

## Ошибки

| Ошибка | Когда | Что делает Dispatcher |
|---|---|---|
| `ErrSourceUnavailable` | источник не ответил после всех повторов | Finder: Job в `failed` с кодом `source_unavailable`. Enricher: Job в `partial`, имя Tool в `missing_sources` |
| `ErrBadResponse` | ответ нельзя разобрать, например HTML вместо JSON | Finder: Job в `failed` с кодом `bad_source_response`. Enricher: как при недоступности |
| `context.Canceled` | пользователь отменил Job | Job в `cancelled`, результат отбрасывается |
| любая другая | ошибка в коде Tool | Job в `failed` с кодом `internal_error`, запись в лог |

Отдельная битая запись в ответе источника не считается ошибкой Tool. Tool пропускает её, пишет в лог с correlation ID и продолжает.

## Кто что проверяет

* **HTTP API** проверяет запрос до создания Job: формат CycloneDX, лимиты размера и числа компонентов, что каждый источник из `sources` есть в Registry.
* **Tool** доверяет данным от Dispatcher и параметры запроса не проверяет. Tool отвечает за проверку ответа своего источника, это делает его адаптер.
* **Dispatcher** решает итоговое состояние Job по ролям и ошибкам Tool. Сам Tool состояние Job не меняет.

## Правила для любого Tool

* Не меняет состояние Job и не пишет в базу. Исключение только у KEVSource: его адаптер хранит кэш каталога через `JobRepository`.
* Не ставит уровни. Это делает Prioritizer после всех Tool.
* Не меняет значения, полученные от другого Tool.
* Для одних и тех же входных данных и одного ответа источника возвращает один и тот же результат.

## Tool проекта

| | OSVSource | KEVSource | EPSSSource |
|---|---|---|---|
| Name | `osv` | `kev` | `epss` |
| Role | Finder | Enricher | Enricher |
| Получает | компоненты SBOM | находки с CVE | находки с CVE |
| Возвращает | находки: идентификаторы с учётом `aliases`, пакет, CVSS из вектора, исправленные версии, признак вредоносного пакета. Компоненты без версии в `Skipped` | те же находки с полем `in_kev` | те же находки с полем `epss` |
| Адаптер | OSVClient: `POST /v1/querybatch` пачками до 1000 компонентов, затем `GET /v1/vulns/{id}` | KEVClient: JSON-каталог CISA, кэш на сутки, при недоступности кэш до 7 дней с датой в `DataDate` | EPSSClient: `GET /data/v1/epss?cve=...` пачками по 100 CVE |
| Таймаут и повторы | 10 секунд на запрос, 3 повтора с паузами 1, 2 и 4 секунды | так же | так же |
| Находки без CVE | склеивает по `aliases` | пропускает, `in_kev = false` | пропускает, `epss = null` |
