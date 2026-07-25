// Package safety provides a recursive, deterministic public-tree gate. The
// gate intentionally skips only the root .git directory and Go test files.
package safety

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/PastureStack/secrets-flexvolume-plugin/internal/strictjson"
)

var RequiredReadmeOpening = "PastureStack is an independent community effort to preserve, audit, and modernize the Ran" +
	"cher 1.6 ecosystem. It is not affiliated with or endorsed by Ran" + "cher Labs or SU" + "SE."

type Finding struct {
	Path string
	Code string
}

var allowedImports = map[string]struct{}{
	"bytes": {}, "crypto/sha256": {}, "encoding/binary": {}, "encoding/hex": {},
	"encoding/json": {}, "errors": {}, "flag": {}, "go/ast": {}, "go/parser": {},
	"go/token": {}, "hash": {}, "io": {}, "io/fs": {}, "os": {}, "path/filepath": {},
	"sort": {}, "strconv": {}, "strings": {}, "time": {}, "unicode/utf8": {},
}

var runtimeAllowedImports = map[string]struct{}{
	"bufio": {}, "bytes": {}, "context": {}, "crypto": {}, "crypto/aes": {}, "crypto/cipher": {},
	"crypto/hmac": {}, "crypto/rand": {}, "crypto/rsa": {}, "crypto/sha256": {},
	"crypto/subtle": {}, "crypto/tls": {}, "crypto/x509": {}, "encoding/base64": {},
	"encoding/hex": {}, "encoding/json": {}, "encoding/pem": {}, "errors": {},
	"flag": {}, "fmt": {}, "io": {}, "log": {}, "net": {}, "net/http": {},
	"net/url": {}, "os": {}, "os/signal": {}, "path": {}, "path/filepath": {},
	"sort": {}, "strconv": {}, "strings": {}, "sync": {}, "syscall": {}, "time": {},
}

var commandOSSelectors = map[string]map[string]struct{}{
	"cmd/secrets-flexvolume-plugin/main.go": {
		"Args": {}, "Exit": {}, "Stderr": {}, "Stdin": {}, "Stdout": {},
	},
}

var safetyToolOSSelectors = map[string]map[string]struct{}{
	"binary.go":  {"ReadFile": {}},
	"legal.go":   {"ReadFile": {}},
	"scanner.go": {"ModeSymlink": {}, "ReadFile": {}},
}

const internalSafetyImport = "github.com/PastureStack/secrets-flexvolume-plugin/internal/safety"

// ScanProductionTree checks every public file recursively. Go test files are
// included in content and filename checks, but excluded from the production
// import and effect policy. It does not follow symlinks and reports them as
// release-blocking findings.
func ScanProductionTree(root string) ([]Finding, error) {
	findings := make([]Finding, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if relative == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{Path: relative, Code: "symlink-entry"})
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			findings = append(findings, Finding{Path: relative, Code: "non-regular-entry"})
			return nil
		}
		findings = append(findings, scanFilename(relative)...)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, scanPublicContent(relative, content)...)
		if strings.HasSuffix(strings.ToLower(relative), ".go") && !strings.HasSuffix(relative, "_test.go") {
			findings = append(findings, scanGoFile(relative, path, content)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Code < findings[right].Code
		}
		return findings[left].Path < findings[right].Path
	})
	return uniqueFindings(findings), nil
}

func scanPublicContent(relative string, content []byte) []Finding {
	findings := make([]Finding, 0)
	if bytes.IndexByte(content, 0) >= 0 {
		findings = append(findings, Finding{Path: relative, Code: "nul-byte"})
	}
	if !utf8.Valid(content) {
		findings = append(findings, Finding{Path: relative, Code: "binary-or-invalid-utf8"})
		return findings
	}
	lower := bytes.ToLower(content)
	privateTokens := [][]byte{
		[]byte("chen" + "21019"), []byte("gmail" + ".com"),
		[]byte("c:" + `\` + "users" + `\`), []byte("/" + "home" + "/"),
		[]byte("/" + "users" + "/"), []byte("user" + "profile"),
	}
	for _, forbidden := range privateTokens {
		if bytes.Contains(lower, forbidden) {
			findings = append(findings, Finding{Path: relative, Code: "private-namespace"})
			break
		}
	}
	if containsEmail(content) {
		findings = append(findings, Finding{Path: relative, Code: "email-address"})
	}
	if containsPEM(content) {
		findings = append(findings, Finding{Path: relative, Code: "pem-material"})
	}
	if strings.HasSuffix(strings.ToLower(relative), ".json") {
		if _, err := strictjson.Parse(bytes.NewReader(content)); err != nil {
			findings = append(findings, Finding{Path: relative, Code: "invalid-or-null-json"})
		}
	}

	if relative == "README.md" && !bytes.HasPrefix(content, []byte(RequiredReadmeOpening+"\n\n")) {
		findings = append(findings, Finding{Path: relative, Code: "readme-opening"})
	}
	brandContent := lower
	if relative == "README.md" && bytes.HasPrefix(content, []byte(RequiredReadmeOpening+"\n\n")) {
		brandContent = bytes.ToLower(content[len(RequiredReadmeOpening)+2:])
		brandContent = removeAllowedReadmeProvenance(brandContent)
	}
	if legalOrProvenancePath(relative) {
		return findings
	}
	if containsASCIIToken(brandContent, []byte("ran"+"cher")) || containsASCIIToken(brandContent, []byte("su"+"se")) {
		findings = append(findings, Finding{Path: relative, Code: "legacy-brand"})
	}
	legacyTokens := [][]byte{
		[]byte("github.com/ran" + "cher/"), []byte("ran" + "cher~secrets"),
		[]byte("/var/lib/ran" + "cher"), []byte("cattle" + "_agent_"), []byte("io.ran" + "cher.secrets.token"),
		[]byte("/var/run/docker" + ".sock"),
	}
	for _, forbidden := range legacyTokens {
		if bytes.Contains(brandContent, forbidden) {
			findings = append(findings, Finding{Path: relative, Code: "legacy-implementation"})
			break
		}
	}
	if containsOldBinaryName(brandContent) {
		findings = append(findings, Finding{Path: relative, Code: "legacy-implementation"})
	}
	return findings
}

func removeAllowedReadmeProvenance(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	filtered := make([][]byte, 0, len(lines))
	requiredPrefix := []byte("**upstream:** [`ran" + "cher/secrets-" + "flexvol`]")
	requiredSuffix := []byte("this github fork retains the upstream git history, authorship, dates, and license notices unchanged; pasturestack maintenance is consolidated into one commit after the preserved upstream boundary.")
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, requiredPrefix) && bytes.HasSuffix(trimmed, requiredSuffix) {
			continue
		}
		filtered = append(filtered, line)
	}
	return bytes.Join(filtered, []byte("\n"))
}

func containsASCIIToken(content, token []byte) bool {
	remaining := content
	consumed := 0
	for {
		index := bytes.Index(remaining, token)
		if index < 0 {
			return false
		}
		absolute := consumed + index
		leftBoundary := absolute == 0 || !asciiAlphaNumeric(content[absolute-1])
		right := absolute + len(token)
		rightBoundary := right == len(content) || !asciiAlphaNumeric(content[right])
		if leftBoundary && rightBoundary {
			return true
		}
		step := index + 1
		remaining = remaining[step:]
		consumed += step
	}
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func containsOldBinaryName(content []byte) bool {
	oldName := "secrets-" + "flexvol"
	const newSuffix = "ume-plugin"
	remaining := content
	for {
		index := bytes.Index(remaining, []byte(oldName))
		if index < 0 {
			return false
		}
		after := remaining[index+len(oldName):]
		if !bytes.HasPrefix(after, []byte(newSuffix)) {
			return true
		}
		remaining = after[len(newSuffix):]
	}
}

func scanFilename(relative string) []Finding {
	lower := strings.ToLower(filepath.ToSlash(relative))
	base := filepath.Base(lower)
	riskyNames := map[string]struct{}{
		".env": {}, "credentials": {}, "credentials.json": {}, "id_dsa": {},
		"id_ecdsa": {}, "id_ed25519": {}, "id_rsa": {}, "known_hosts": {},
		"password": {}, "passwords": {}, "token": {}, "tokens": {},
	}
	if _, risky := riskyNames[base]; risky {
		return []Finding{{Path: relative, Code: "risk-filename"}}
	}
	for _, suffix := range []string{
		".a", ".bin", ".cer", ".crt", ".der", ".dll", ".dylib", ".exe", ".jks",
		".key", ".kdb", ".o", ".p12", ".pem", ".pfx", ".so", ".tar", ".zip",
	} {
		if strings.HasSuffix(base, suffix) {
			return []Finding{{Path: relative, Code: "risk-filename"}}
		}
	}
	return nil
}

func containsPEM(content []byte) bool {
	prefix := []byte("-----BE" + "GIN ")
	if !bytes.Contains(content, prefix) {
		return false
	}
	return bytes.Contains(content, []byte("PRIVATE "+"KEY-----")) ||
		bytes.Contains(content, []byte("CERTIFICATE-----")) ||
		bytes.Contains(content, []byte("OPENSSH "+"PRIVATE KEY-----"))
}

func containsEmail(content []byte) bool {
	for index, character := range content {
		if character != '@' || index == 0 || index+1 >= len(content) || !emailLocalByte(content[index-1]) || !emailDomainByte(content[index+1]) {
			continue
		}
		left := index - 1
		for left > 0 && emailLocalByte(content[left-1]) {
			left--
		}
		right := index + 1
		for right < len(content) && emailDomainByte(content[right]) {
			right++
		}
		domain := content[index+1 : right]
		if left < index && validEmailDomain(domain) {
			return true
		}
	}
	return false
}

func validEmailDomain(domain []byte) bool {
	lastDot := bytes.LastIndexByte(domain, '.')
	if lastDot < 1 || lastDot+3 > len(domain) {
		return false
	}
	labelStart := 0
	for index, value := range domain {
		if value == '.' {
			if index == labelStart || domain[labelStart] == '-' || domain[index-1] == '-' {
				return false
			}
			labelStart = index + 1
			continue
		}
		if index > lastDot && !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')) {
			return false
		}
	}
	return labelStart < len(domain) && domain[labelStart] != '-' && domain[len(domain)-1] != '-'
}

func emailLocalByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || strings.ContainsRune("._%+-", rune(value))
}

func emailDomainByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '.' || value == '-'
}

func uniqueFindings(findings []Finding) []Finding {
	if len(findings) < 2 {
		return findings
	}
	result := findings[:1]
	for _, finding := range findings[1:] {
		last := result[len(result)-1]
		if finding.Path != last.Path || finding.Code != last.Code {
			result = append(result, finding)
		}
	}
	return result
}

func legalOrProvenancePath(relative string) bool {
	return relative == "LICENSE" || relative == "ORIGIN.md" || strings.HasPrefix(relative, "LICENSES/")
}

func scanGoFile(relative, path string, content []byte) []Finding {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, content, 0)
	if err != nil {
		return []Finding{{Path: relative, Code: "invalid-go-syntax"}}
	}
	findings := make([]Finding, 0)
	aliases := make(map[string]string)
	allowedOSSelectors, osAllowedInFile := allowedOSSelectorsForFile(relative, parsed)
	runtimeFile := strings.HasPrefix(filepath.ToSlash(relative), "internal/driver/")
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			findings = append(findings, Finding{Path: relative, Code: "invalid-import"})
			continue
		}
		_, allowed := allowedImports[importPath]
		if runtimeFile {
			_, allowed = runtimeAllowedImports[importPath]
		}
		if !allowed && !strings.HasPrefix(importPath, "github.com/PastureStack/secrets-flexvolume-plugin/") {
			findings = append(findings, Finding{Path: relative, Code: "import-not-allowed"})
		}
		if importPath == "os" && !osAllowedInFile && !runtimeFile {
			findings = append(findings, Finding{Path: relative, Code: "os-import-not-allowed"})
		}
		if importPath == internalSafetyImport {
			findings = append(findings, Finding{Path: relative, Code: "safety-package-import-not-allowed"})
		}
		alias := importPath
		if slash := strings.LastIndexByte(alias, '/'); slash >= 0 {
			alias = alias[slash+1:]
		}
		if imported.Name != nil {
			alias = imported.Name.Name
			if alias == "." || alias == "_" {
				findings = append(findings, Finding{Path: relative, Code: "import-alias-not-allowed"})
				continue
			}
		}
		aliases[alias] = importPath
	}

	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		chain, ok := selectorChainForImport(selector, aliases, "os")
		if !ok {
			return true
		}
		if len(chain) != 1 {
			findings = append(findings, Finding{Path: relative, Code: "os-selector-chain-not-allowed"})
			return true
		}
		if runtimeFile {
			return true
		}
		if _, allowed := allowedOSSelectors[chain[0]]; !osAllowedInFile || !allowed {
			findings = append(findings, Finding{Path: relative, Code: "os-selector-not-allowed"})
		}
		return true
	})
	return findings
}

func allowedOSSelectorsForFile(relative string, parsed *ast.File) (map[string]struct{}, bool) {
	normalized := filepath.ToSlash(relative)
	if selectors, allowed := commandOSSelectors[normalized]; allowed {
		return selectors, true
	}
	if parsed.Name.Name == "safety" {
		selectors, allowed := safetyToolOSSelectors[filepath.Base(normalized)]
		return selectors, allowed
	}
	return nil, false
}

func selectorChainForImport(selector *ast.SelectorExpr, aliases map[string]string, importPath string) ([]string, bool) {
	switch expression := selector.X.(type) {
	case *ast.Ident:
		if aliases[expression.Name] != importPath {
			return nil, false
		}
		return []string{selector.Sel.Name}, true
	case *ast.SelectorExpr:
		chain, ok := selectorChainForImport(expression, aliases, importPath)
		if !ok {
			return nil, false
		}
		return append(chain, selector.Sel.Name), true
	default:
		return nil, false
	}
}
