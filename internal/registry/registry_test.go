package registry_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/AIProgramIngeneering2026/team-kepler22/internal/registry"
	"github.com/AIProgramIngeneering2026/team-kepler22/internal/tool"
)

type stub struct{ name string }

func (s stub) Name() string      { return s.name }
func (stub) Role() tool.Role     { return tool.Finder }
func (stub) Description() string { return "stub" }
func (stub) Run(context.Context, tool.Input) (tool.Result, error) {
	return tool.Result{}, nil
}

func TestGetKnownTool(t *testing.T) {
	r, err := registry.New(stub{"osv"}, stub{"kev"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get("kev")
	if err != nil || got.Name() != "kev" {
		t.Fatalf("Get(kev) = %v, %v", got, err)
	}
	if want := []string{"kev", "osv"}; !reflect.DeepEqual(r.Names(), want) {
		t.Fatalf("Names = %v, want %v", r.Names(), want)
	}
}

func TestUnknownTool(t *testing.T) {
	r, _ := registry.New(stub{"osv"})
	for _, name := range []string{"nvd", "", "OSV"} {
		if _, err := r.Get(name); !errors.Is(err, registry.ErrUnknownTool) {
			t.Fatalf("Get(%q): ожидали ErrUnknownTool, получили %v", name, err)
		}
	}
}

func TestRegisterRejectsDuplicateAndEmpty(t *testing.T) {
	r, _ := registry.New(stub{"osv"})
	if err := r.Register(stub{"osv"}); !errors.Is(err, registry.ErrDuplicateTool) {
		t.Fatalf("дубликат: %v", err)
	}
	if err := r.Register(stub{""}); !errors.Is(err, registry.ErrBadTool) {
		t.Fatalf("пустое имя: %v", err)
	}
	if err := r.Register(nil); !errors.Is(err, registry.ErrBadTool) {
		t.Fatalf("nil: %v", err)
	}
}
