// Package archtest проверяет, что ядро не зависит от веб-фреймворка и базы данных.
package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/AIProgramIngeneering2026/team-kepler22"

// core это пакеты ядра. Адаптеры к HTTP и PostgreSQL будут жить вне этого списка.
var core = []string{"vuln", "job", "tool", "registry", "dispatcher", "runner", "service", "tools", "storage/memory"}

// forbidden запрещены в ядре, хотя и входят в стандартную библиотеку.
var forbidden = []string{"net/http", "database/sql"}

func TestCoreHasNoFrameworkOrDB(t *testing.T) {
	fset := token.NewFileSet()
	for _, dir := range core {
		root := filepath.Join("..", dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				first := strings.Split(p, "/")[0]
				if strings.Contains(first, ".") && !strings.HasPrefix(p, module) {
					t.Errorf("%s: внешняя зависимость %s в ядре", path, p)
				}
				for _, bad := range forbidden {
					if p == bad || strings.HasPrefix(p, bad+"/") {
						t.Errorf("%s: %s в ядре запрещён", path, p)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
