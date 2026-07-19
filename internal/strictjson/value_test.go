package strictjson

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseAcceptsOneCanonicalDocument(t *testing.T) {
	value, err := Parse(strings.NewReader(`{"a":1,"b":[true,"x"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if value.Kind != KindObject || value.Object["a"].Number != "1" {
		t.Fatal("unexpected decoded value")
	}
}

func TestParseRejectsStrictJSONViolations(t *testing.T) {
	deep := strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1)
	tests := map[string][]byte{
		"empty":          {},
		"bom":            append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"a":1}`)...),
		"invalid utf8":   {0xff, 0xfe},
		"duplicate root": []byte(`{"a":1,"a":2}`),
		"duplicate deep": []byte(`{"a":{"b":1,"b":2}}`),
		"null root":      []byte(`null`),
		"null deep":      []byte(`{"a":[null]}`),
		"multiple":       []byte(`{"a":1} {"b":2}`),
		"exponent":       []byte(`{"a":1e2}`),
		"fraction":       []byte(`{"a":1.0}`),
		"negative":       []byte(`{"a":-1}`),
		"too deep":       []byte(deep),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(bytes.NewReader(input)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	input := `{"a":"` + strings.Repeat("x", MaxInputBytes) + `"}`
	if _, err := Parse(strings.NewReader(input)); err == nil {
		t.Fatal("expected oversized input to be rejected")
	}
}
