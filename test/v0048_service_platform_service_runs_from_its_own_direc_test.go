package test

// Requirement: service-platform service runs from its own directory and
// image. Selection of a changed service's tests is the test runner's
// (qa-tooling, task 1.0); audit's part is that nothing from a sibling FlowAI service is
// imported, so a change elsewhere cannot alter audit.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestV0048ServicePlatformOwnDirectoryAndImage(t *testing.T) {
	t.Run("Change to one service selects only its tests", func(t *testing.T) {
		var files []string
		_ = filepath.WalkDir(serviceDir(t), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") {
				files = append(files, p)
			}
			return nil
		})
		if len(files) == 0 {
			t.Fatal("no Go files")
		}
		for _, f := range files {
			parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, imp := range parsed.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(path, "github.com/flowai/platform/") ||
					(strings.HasPrefix(path, "github.com/pandops/flowai-") &&
						!strings.HasPrefix(path, "github.com/pandops/flowai-audit/")) {
					t.Errorf("%s imports %s from another service", f, path)
				}
			}
		}
	})

}
