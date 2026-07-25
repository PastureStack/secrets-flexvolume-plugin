//go:build publictree

package safety

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestPublicCurrentTree is an explicit manual release gate. It is intentionally
// excluded from ordinary targeted tests while the audited legacy tree remains.
func TestPublicCurrentTree(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to locate repository")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("public tree gate found %d issue(s): %v", len(findings), findings)
	}
}
