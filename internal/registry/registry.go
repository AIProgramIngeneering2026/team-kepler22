// Package registry выдаёт Tool по имени.
package registry

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
)

var (
	// ErrUnknownTool: Tool с таким именем не зарегистрирован. В API это код unknown_tool.
	ErrUnknownTool = errors.New("unknown_tool")
	// ErrDuplicateTool: имя уже занято.
	ErrDuplicateTool = errors.New("duplicate_tool")
	// ErrBadTool: у Tool пустое имя или Tool равен nil.
	ErrBadTool = errors.New("bad_tool")
)

// Registry хранит Tool по именам. Безопасен для одновременного чтения.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]tool.Tool
}

// New создаёт Registry и регистрирует переданные Tool.
func New(tools ...tool.Tool) (*Registry, error) {
	r := &Registry{tools: make(map[string]tool.Tool)}
	for _, t := range tools {
		if err := r.Register(t); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register добавляет Tool. Новый источник подключается только здесь, Dispatcher не меняется.
func (r *Registry) Register(t tool.Tool) error {
	if t == nil || t.Name() == "" {
		return ErrBadTool
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tools[t.Name()]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicateTool, t.Name())
	}
	r.tools[t.Name()] = t
	return nil
}

// Get возвращает Tool по имени или ErrUnknownTool.
func (r *Registry) Get(name string) (tool.Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}
	return t, nil
}

// Names возвращает имена всех Tool по алфавиту.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
