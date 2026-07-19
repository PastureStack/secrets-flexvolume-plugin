package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const HistoricalManifestPath = "LICENSES/HISTORICAL-MANIFEST.json"

type legalArtifact struct {
	ID             string `json:"id"`
	File           string `json:"file"`
	Package        string `json:"package,omitempty"`
	OriginalPath   string `json:"originalPath,omitempty"`
	Classification string `json:"classification"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
}

type legalManifest struct {
	SchemaVersion         uint64 `json:"schemaVersion"`
	Status                string `json:"status"`
	Notice                string `json:"notice"`
	CurrentImplementation struct {
		Module                           string `json:"module"`
		DependencyModel                  string `json:"dependencyModel"`
		HistoricalArtifactsUsedAtRuntime bool   `json:"historicalArtifactsUsedAtRuntime"`
	} `json:"currentImplementation"`
	RootLicense        legalArtifact   `json:"rootLicense"`
	Artifacts          []legalArtifact `json:"artifacts"`
	GoToolchainNotices []legalArtifact `json:"goToolchainNotices"`
}

var expectedLegalArtifacts = []legalArtifact{
	{ID: "root-license", File: "LICENSE", Classification: "Apache-2.0", Bytes: 10351, SHA256: "eb3d7b5485466acbd81f2b496f595ab637d2792e268206b27d99e793bdb67549"},
	{ID: "dependency-01", File: "LICENSES/historical/dependency-01.txt", Classification: "Apache-2.0", Bytes: 10174, SHA256: "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594"},
	{
		ID: "dependency-02", File: "LICENSES/historical/dependency-02.txt", Classification: "MIT",
		Bytes: 1082, SHA256: "51a0c9ec7f8b7634181b8d4c03e5b5d204ac21d6e72f46c313973424664b2e6b",
	},
	{
		ID: "dependency-03", File: "LICENSES/historical/dependency-03.txt", Classification: "MIT",
		Bytes: 1084, SHA256: "da277af11b85227490377fbcac6afccc68be560c4fff36ac05ca62de55345fd7",
	},
	{
		ID: "dependency-04", File: "LICENSES/historical/dependency-04.txt", Classification: "BSD-3-Clause",
		Bytes: 1453, SHA256: "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
	},
	{ID: "go-license", File: "LICENSES/GO-LICENSE", Classification: "BSD-3-Clause", Bytes: 1453, SHA256: "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"},
	{ID: "go-patents", File: "LICENSES/GO-PATENTS", Classification: "Additional IP Rights Grant (Patents)", Bytes: 1303, SHA256: "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"},
}

const (
	expectedHistoricalManifestBytes  = 2535
	expectedHistoricalManifestSHA256 = "d47f810db385f63a39169a5d6f879fc34717179be593213f0bab2d7bf771247c"
)

// VerifyLegalArtifacts checks every byte-preserved legal artifact and the
// manifest that distinguishes the current standard-library implementation from
// historical dependency evidence.
func VerifyLegalArtifacts(root string) ([]Finding, error) {
	findings := make([]Finding, 0)
	for _, expected := range expectedLegalArtifacts {
		path := filepath.Join(root, filepath.FromSlash(expected.File))
		content, err := os.ReadFile(path)
		if err != nil {
			findings = append(findings, Finding{Path: expected.File, Code: "legal-artifact-missing"})
			continue
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != expected.Bytes || hex.EncodeToString(digest[:]) != expected.SHA256 {
			findings = append(findings, Finding{Path: expected.File, Code: "legal-artifact-mismatch"})
		}
	}

	manifestPath := filepath.Join(root, filepath.FromSlash(HistoricalManifestPath))
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-missing"})
	} else {
		manifestDigest := sha256.Sum256(manifestData)
		if len(manifestData) != expectedHistoricalManifestBytes || hex.EncodeToString(manifestDigest[:]) != expectedHistoricalManifestSHA256 {
			findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-mismatch"})
		}
		var manifest legalManifest
		if json.Unmarshal(manifestData, &manifest) != nil {
			findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-invalid"})
		} else {
			findings = append(findings, verifyLegalManifest(manifest)...)
		}
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Code < findings[right].Code
		}
		return findings[left].Path < findings[right].Path
	})
	return uniqueFindings(findings), nil
}

func verifyLegalManifest(manifest legalManifest) []Finding {
	findings := make([]Finding, 0)
	if manifest.SchemaVersion != 1 || manifest.Status != "historical-only" ||
		!strings.Contains(manifest.Notice, "standard-library-only") || !strings.Contains(manifest.Notice, "does not import or use") {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-boundary"})
	}
	if manifest.CurrentImplementation.Module != "github.com/PastureStack/secrets-flexvolume-plugin" ||
		manifest.CurrentImplementation.DependencyModel != "Go standard library only" ||
		manifest.CurrentImplementation.HistoricalArtifactsUsedAtRuntime {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-current-implementation"})
	}
	if !sameLegalRecord(manifest.RootLicense, expectedLegalArtifacts[0], false) {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "root-license-record-mismatch"})
	}
	expectedRecords := make(map[string]legalArtifact)
	for _, artifact := range expectedLegalArtifacts[1:] {
		expectedRecords[artifact.ID] = artifact
	}
	actualRecords := append(append([]legalArtifact(nil), manifest.Artifacts...), manifest.GoToolchainNotices...)
	if len(actualRecords) != len(expectedRecords) {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-record-count"})
	}
	for _, actual := range actualRecords {
		expected, exists := expectedRecords[actual.ID]
		requiresAttribution := exists && strings.HasPrefix(expected.ID, "dependency-")
		if !exists || !sameLegalRecord(actual, expected, requiresAttribution) {
			findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-record-mismatch"})
		}
		delete(expectedRecords, actual.ID)
	}
	if len(expectedRecords) != 0 {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-record-missing"})
	}
	return findings
}

func sameLegalRecord(actual, expected legalArtifact, historical bool) bool {
	if actual.ID != expected.ID || actual.File != expected.File || actual.Classification != expected.Classification ||
		actual.Bytes != expected.Bytes || actual.SHA256 != expected.SHA256 {
		return false
	}
	if historical {
		return actual.Package != "" && actual.OriginalPath != ""
	}
	return actual.Package == "" && actual.OriginalPath == ""
}
