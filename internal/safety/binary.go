package safety

import (
	"bytes"
	"os"
	"sort"
)

// ScanBinary checks a built command for embedded private namespaces, local
// home paths, email addresses, PEM material, and historical implementation
// identifiers. NUL bytes are expected in executable formats and are ignored.
func ScanBinary(path string) ([]Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, 0)
	if !isExecutableFormat(content) {
		findings = append(findings, Finding{Path: filepathBase(path), Code: "unknown-binary-format"})
	}
	lower := bytes.ToLower(content)
	for _, forbidden := range [][]byte{
		[]byte("chen" + "21019"), []byte("gmail" + ".com"),
		[]byte("c:" + `\` + "users" + `\`), []byte("/" + "home" + "/"), []byte("/" + "users" + "/"),
	} {
		if bytes.Contains(lower, forbidden) {
			findings = append(findings, Finding{Path: filepathBase(path), Code: "private-binary-metadata"})
			break
		}
	}
	if containsEmail(content) {
		findings = append(findings, Finding{Path: filepathBase(path), Code: "email-in-binary"})
	}
	if containsPEM(content) {
		findings = append(findings, Finding{Path: filepathBase(path), Code: "pem-in-binary"})
	}
	if containsASCIIToken(lower, []byte("ran"+"cher")) || containsASCIIToken(lower, []byte("su"+"se")) || containsOldBinaryName(lower) {
		findings = append(findings, Finding{Path: filepathBase(path), Code: "legacy-binary-metadata"})
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Code < findings[right].Code
		}
		return findings[left].Path < findings[right].Path
	})
	return uniqueFindings(findings), nil
}

func isExecutableFormat(content []byte) bool {
	return len(content) >= 4 && (bytes.HasPrefix(content, []byte{'M', 'Z'}) || bytes.Equal(content[:4], []byte{0x7f, 'E', 'L', 'F'}))
}

func filepathBase(path string) string {
	lastSlash := bytes.LastIndexAny([]byte(path), `/\`)
	if lastSlash < 0 {
		return path
	}
	return path[lastSlash+1:]
}
