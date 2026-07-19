// Package cli implements the side-effect-free command-line interface.
package cli

import (
	"encoding/json"
	"flag"
	"io"
	"sort"

	"github.com/PastureStack/secrets-flexvolume-plugin/internal/model"
	"github.com/PastureStack/secrets-flexvolume-plugin/internal/strictjson"
)

const (
	LocaleEnglish = "en-US"
	LocaleChinese = "zh-TW"
)

type capabilityOutput struct {
	Status          string         `json:"status"`
	Locale          string         `json:"locale"`
	APIVersions     []string       `json:"apiVersions"`
	Commands        []string       `json:"commands"`
	Operations      []string       `json:"operations"`
	MaxInputBytes   int            `json:"maxInputBytes"`
	ManifestVersion uint64         `json:"manifestVersion"`
	Controls        model.Controls `json:"controls"`
}

type diagnosticOutput struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type validateOutput struct {
	Status      string                `json:"status"`
	Locale      string                `json:"locale"`
	Summary     model.Summary         `json:"summary"`
	Assertions  model.AssertionStatus `json:"assertions"`
	Diagnostics []diagnosticOutput    `json:"diagnostics"`
	Controls    model.Controls        `json:"controls"`
}

type planOutput struct {
	Status      string                `json:"status"`
	Locale      string                `json:"locale"`
	PlanID      string                `json:"planId"`
	Operation   string                `json:"operation"`
	Transition  model.Transition      `json:"transition"`
	Summary     model.Summary         `json:"summary"`
	Assertions  model.AssertionStatus `json:"assertions"`
	Steps       []model.Step          `json:"steps"`
	Gates       []model.Gate          `json:"gates"`
	Diagnostics []diagnosticOutput    `json:"diagnostics"`
	Controls    model.Controls        `json:"controls"`
}

type errorOutput struct {
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Run executes one CLI request and returns a process exit code. The
// capabilities command deliberately never touches stdin.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("secrets-flexvolume-plugin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	locale := flags.String("locale", LocaleEnglish, "")
	if err := flags.Parse(args); err != nil || !validLocale(*locale) {
		writeGenericError(stderr, chooseLocale(*locale), "invalid-usage")
		return 2
	}
	rest := flags.Args()
	if len(rest) != 1 {
		writeGenericError(stderr, *locale, "invalid-usage")
		return 2
	}

	switch rest[0] {
	case "capabilities":
		output := capabilityOutput{
			Status:          "ok",
			Locale:          *locale,
			APIVersions:     []string{model.APIVersion},
			Commands:        []string{"capabilities", "plan", "validate"},
			Operations:      []string{"activate", "cleanup", "revoke", "rotate", "stage"},
			MaxInputBytes:   strictjson.MaxInputBytes,
			ManifestVersion: model.ManifestVersion,
			Controls:        model.DisabledControls(),
		}
		if !writeJSON(stdout, output) {
			writeGenericError(stderr, *locale, "internal-error")
			return 1
		}
		return 0
	case "validate", "plan":
		request, err := model.Parse(stdin)
		if err != nil {
			writeGenericError(stderr, *locale, "invalid-input")
			return 2
		}
		if rest[0] == "validate" {
			diagnosticCodes := []string{"effects-disabled", "source-assertions-unverified", "state-unverified"}
			sort.Strings(diagnosticCodes)
			output := validateOutput{
				Status:      "valid",
				Locale:      *locale,
				Summary:     model.RequestSummary(request),
				Assertions:  model.UnverifiedAssertions(),
				Diagnostics: localizedDiagnostics(*locale, diagnosticCodes),
				Controls:    model.DisabledControls(),
			}
			if !writeJSON(stdout, output) {
				writeGenericError(stderr, *locale, "internal-error")
				return 1
			}
			return 0
		}

		plan := model.BuildPlan(request)
		output := planOutput{
			Status:      "planned",
			Locale:      *locale,
			PlanID:      plan.PlanID,
			Operation:   plan.Operation,
			Transition:  plan.Transition,
			Summary:     plan.Summary,
			Assertions:  plan.Assertions,
			Steps:       plan.Steps,
			Gates:       plan.Gates,
			Diagnostics: localizedDiagnostics(*locale, plan.Diagnostics),
			Controls:    plan.Controls,
		}
		if !writeJSON(stdout, output) {
			writeGenericError(stderr, *locale, "internal-error")
			return 1
		}
		return 0
	default:
		writeGenericError(stderr, *locale, "invalid-usage")
		return 2
	}
}

func validLocale(locale string) bool {
	return locale == LocaleEnglish || locale == LocaleChinese
}

func chooseLocale(locale string) string {
	if locale == LocaleChinese {
		return LocaleChinese
	}
	return LocaleEnglish
}

func writeGenericError(destination io.Writer, locale, code string) {
	_ = writeJSON(destination, errorOutput{
		Status:  "error",
		Code:    code,
		Message: message(locale, code),
	})
}

func localizedDiagnostics(locale string, codes []string) []diagnosticOutput {
	result := make([]diagnosticOutput, 0, len(codes))
	for _, code := range codes {
		result = append(result, diagnosticOutput{Code: code, Message: message(locale, code)})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Code < result[right].Code })
	return result
}

func message(locale, code string) string {
	if locale == LocaleChinese {
		switch code {
		case "invalid-input":
			return "輸入已遭拒絕。"
		case "invalid-usage":
			return "命令用法無效。"
		case "effects-disabled":
			return "所有外部效果皆已停用。"
		case "source-assertions-unverified":
			return "來源聲明未經驗證。"
		case "state-unverified":
			return "生命週期狀態未經外部驗證。"
		default:
			return "作業無法完成。"
		}
	}
	switch code {
	case "invalid-input":
		return "The input was rejected."
	case "invalid-usage":
		return "The command usage is invalid."
	case "effects-disabled":
		return "All external effects are disabled."
	case "source-assertions-unverified":
		return "Source assertions are unverified."
	case "state-unverified":
		return "Lifecycle state is not externally verified."
	default:
		return "The operation could not be completed."
	}
}

func writeJSON(destination io.Writer, value any) bool {
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value) == nil
}
