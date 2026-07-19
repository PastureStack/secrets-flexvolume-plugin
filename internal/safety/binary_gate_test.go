package safety

import (
	"os"
	"testing"
)

func TestExternalBinaryGate(t *testing.T) {
	path := os.Getenv("SECRETS_FLEXVOLUME_PLUGIN_BINARY")
	if path == "" {
		t.Skip("external binary path is not set")
	}
	findings, err := ScanBinary(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("binary gate found %d issue(s): %v", len(findings), findings)
	}
}
