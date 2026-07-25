package safety

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryScannerRequiresBrandTokenBoundaries(t *testing.T) {
	path := writeBinaryFixture(t, "runtime-collisions.exe", "cgocallersuse isuser misuse runtime.sysused H@G.H")
	findings, err := ScanBinary(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("runtime identifier substring was treated as metadata: %v", findings)
	}
}

func TestBinaryScannerFindsStandaloneLegacyMetadata(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		code    string
	}{
		{name: "repository URL", payload: "https://github.com/ran" + "cher/example", code: "legacy-binary-metadata"},
		{name: "brand token", payload: " SU" + "SE ", code: "legacy-binary-metadata"},
		{name: "old command", payload: "/secrets-" + "flexvol", code: "legacy-binary-metadata"},
		{name: "home path", payload: `C:\Us` + `ers\sample\project`, code: "private-binary-metadata"},
		{name: "private namespace", payload: "chen" + "21019", code: "private-binary-metadata"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := writeBinaryFixture(t, "fixture.exe", test.payload)
			findings, err := ScanBinary(path)
			if err != nil {
				t.Fatal(err)
			}
			if !hasFinding(findings, "fixture.exe", test.code) {
				t.Fatalf("expected %s for fixture, got %v", test.code, findings)
			}
		})
	}
}

func writeBinaryFixture(t *testing.T, name, payload string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	content := append([]byte{'M', 'Z', 0, 0}, []byte(payload)...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
