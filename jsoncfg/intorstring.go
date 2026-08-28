package jsoncfg

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"unsafe"
)

// IntOrStringKind represents the kind of the [IntOrString] value.
type IntOrStringKind int

const (
	IntOrStringKindInvalid IntOrStringKind = iota
	IntOrStringKindInt
	IntOrStringKindString
)

// IntOrString is a JSON value that can be either an int or a string.
type IntOrString struct {
	kind IntOrStringKind
	data *byte
	len  int // also used as storage for int
}

// IntOrStringFromInt returns i as an [IntOrString] value.
func IntOrStringFromInt(i int) IntOrString {
	return IntOrString{
		kind: IntOrStringKindInt,
		len:  i,
	}
}

// IntOrStringFromString returns s as an [IntOrString] value.
func IntOrStringFromString(s string) IntOrString {
	return IntOrString{
		kind: IntOrStringKindString,
		data: unsafe.StringData(s),
		len:  len(s),
	}
}

// Kind returns the value kind.
func (v IntOrString) Kind() IntOrStringKind {
	return v.kind
}

// IsValid returns whether the value is valid.
func (v IntOrString) IsValid() bool {
	return v.kind != IntOrStringKindInvalid
}

// IsInt returns whether the value is an int.
func (v IntOrString) IsInt() bool {
	return v.kind == IntOrStringKindInt
}

// IsString returns whether the value is a string.
func (v IntOrString) IsString() bool {
	return v.kind == IntOrStringKindString
}

// Int returns the int value.
// It panics if the value is not an int.
func (v IntOrString) Int() int {
	if v.kind != IntOrStringKindInt {
		panic("IntOrString: not an int")
	}
	return v.len
}

func (v IntOrString) string() string {
	return unsafe.String(v.data, v.len)
}

// String returns the string value.
// It panics if the value is not a string.
func (v IntOrString) String() string {
	if v.kind != IntOrStringKindString {
		panic("IntOrString: not a string")
	}
	return v.string()
}

// Equals returns whether the value is equal to other.
func (v IntOrString) Equals(other IntOrString) bool {
	if v.kind != other.kind {
		return false
	}
	switch v.kind {
	case IntOrStringKindInt:
		return v.len == other.len
	case IntOrStringKindString:
		return v.string() == other.string()
	default:
		return true
	}
}

// MarshalJSONTo implements [json.MarshalerTo].
func (v IntOrString) MarshalJSONTo(enc *jsontext.Encoder) error {
	var t jsontext.Token
	switch v.kind {
	case IntOrStringKindInt:
		t = jsontext.Int(int64(v.len))
	case IntOrStringKindString:
		t = jsontext.String(v.string())
	default:
		t = jsontext.Null
	}
	return enc.WriteToken(t)
}

// UnmarshalJSONFrom implements [json.UnmarshalerFrom].
func (v *IntOrString) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	t, err := dec.ReadToken()
	if err != nil {
		return err
	}

	switch k := t.Kind(); k {
	case jsontext.KindNull:
		*v = IntOrString{}
	case jsontext.KindNumber:
		i64, err := t.Int()
		if err != nil {
			return &json.SemanticError{JSONKind: k, Err: err}
		}
		i := int(i64)
		if int64(i) != i64 {
			return &json.SemanticError{JSONKind: k, Err: strconv.ErrRange}
		}
		*v = IntOrStringFromInt(i)
	case jsontext.KindString:
		*v = IntOrStringFromString(t.String())
	default:
		return &json.SemanticError{JSONKind: k}
	}

	return nil
}
