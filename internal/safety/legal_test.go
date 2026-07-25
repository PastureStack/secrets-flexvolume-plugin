package safety

import (
	"path/filepath"
	"runtime"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to locate repository")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestLegalArtifactsAndManifest(t *testing.T) {
	findings, err := VerifyLegalArtifacts(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("legal artifact gate found %d issue(s): %v", len(findings), findings)
	}
}
