// Package strictjson decodes the deliberately small JSON surface accepted by
// the metadata-only audit interface. It preserves object keys long enough to reject
// duplicates before schema validation.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	MaxInputBytes = 2 * 1024 * 1024
	MaxDepth      = 16
)

var ErrInvalid = errors.New("invalid JSON input")

type Kind uint8

const (
	KindObject Kind = iota + 1
	KindArray
	KindString
	KindNumber
	KindBool
)

// Value is a null-free JSON value. Number holds the original number token.
type Value struct {
	Kind   Kind
	Object map[string]Value
	Array  []Value
	String string
	Number string
	Bool   bool
}

// Parse reads exactly one JSON document. It rejects UTF-8 BOMs, invalid UTF-8,
// duplicate keys, null at any depth, non-canonical numbers, excessive depth,
// trailing documents, and inputs larger than MaxInputBytes.
func Parse(r io.Reader) (Value, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInputBytes+1))
	if err != nil || len(data) > MaxInputBytes || len(data) == 0 {
		return Value{}, ErrInvalid
	}
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) || !utf8.Valid(data) {
		return Value{}, ErrInvalid
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return Value{}, ErrInvalid
	}
	value, err := parseToken(decoder, token, 1)
	if err != nil {
		return Value{}, ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Value{}, ErrInvalid
	}
	return value, nil
}

func parseToken(decoder *json.Decoder, token json.Token, depth int) (Value, error) {
	if depth > MaxDepth {
		return Value{}, ErrInvalid
	}

	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]Value)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return Value{}, ErrInvalid
				}
				key, ok := keyToken.(string)
				if !ok {
					return Value{}, ErrInvalid
				}
				if _, duplicate := object[key]; duplicate {
					return Value{}, ErrInvalid
				}
				childToken, err := decoder.Token()
				if err != nil {
					return Value{}, ErrInvalid
				}
				child, err := parseToken(decoder, childToken, depth+1)
				if err != nil {
					return Value{}, ErrInvalid
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return Value{}, ErrInvalid
			}
			return Value{Kind: KindObject, Object: object}, nil
		case '[':
			array := make([]Value, 0)
			for decoder.More() {
				childToken, err := decoder.Token()
				if err != nil {
					return Value{}, ErrInvalid
				}
				child, err := parseToken(decoder, childToken, depth+1)
				if err != nil {
					return Value{}, ErrInvalid
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return Value{}, ErrInvalid
			}
			return Value{Kind: KindArray, Array: array}, nil
		default:
			return Value{}, ErrInvalid
		}
	case string:
		return Value{Kind: KindString, String: value}, nil
	case json.Number:
		number := value.String()
		if !canonicalUnsignedNumber(number) {
			return Value{}, ErrInvalid
		}
		return Value{Kind: KindNumber, Number: number}, nil
	case bool:
		return Value{Kind: KindBool, Bool: value}, nil
	case nil:
		return Value{}, ErrInvalid
	default:
		return Value{}, ErrInvalid
	}
}

func canonicalUnsignedNumber(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) == 0 || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
