package plugin

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Bind populates dst from cfg.Args, validates, and sets struct fields.
func Bind(cfg Config, dst any) error {
	paramSlice, err := ParametersFrom(dst)
	if err != nil {
		return err
	}
	params := NewParameters(paramSlice...)

	for k, v := range cfg.Args {
		params.Set(k, v)
	}

	if err := params.Validate(); err != nil {
		return err
	}

	if err := populateStruct(&params, dst); err != nil {
		return err
	}

	return nil
}

// ParametersFrom derives []Parameter from a struct's field tags.
// Supported tags: param, desc, default, enum, shortcode, required, hidden, sensitive.
//
// Every exported, non-embedded field in the struct must have a `param` tag
// (use `param:"-"` to explicitly skip a field). This prevents silent
// misconfiguration where a module author adds a field but forgets to tag it.
func ParametersFrom(v any) ([]Parameter, error) {
	if v == nil {
		return nil, nil
	}
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, nil
	}
	return collectFields(t)
}

func collectFields(t reflect.Type) ([]Parameter, error) {
	var params []Parameter
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		// Walk embedded structs
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			embedded, err := collectFields(f.Type)
			if err != nil {
				return nil, err
			}
			params = append(params, embedded...)
			continue
		}

		name := f.Tag.Get("param")

		// Exported, non-embedded fields without a param tag are an error.
		// Use `param:"-"` to explicitly opt out.
		if name == "" && f.IsExported() {
			return nil, fmt.Errorf("field %q in %s is exported but has no `param` tag (use `param:\"-\"` to skip)", f.Name, t.Name())
		}

		if name == "" || name == "-" {
			continue
		}

		p := Parameter{
			Name:        name,
			Description: f.Tag.Get("desc"),
			Type:        goTypeToParamType(f.Type),
		}

		if def := f.Tag.Get("default"); def != "" {
			p.Default = parseDefault(def, f.Type)
		}
		if enum := f.Tag.Get("enum"); enum != "" {
			p.Enum = strings.Split(enum, ",")
		}
		if f.Tag.Get("required") == "true" {
			p.Required = true
		}
		if sc := f.Tag.Get("shortcode"); sc != "" {
			p.Shortcode = sc
		}
		if f.Tag.Get("hidden") == "true" {
			p.Hidden = true
		}
		if f.Tag.Get("sensitive") == "true" {
			p.Sensitive = true
		}

		params = append(params, p)
	}
	return params, nil
}

func populateStruct(ps *Parameters, dst any) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("bind: dst must be a pointer to a struct")
	}
	v = v.Elem()
	t := v.Type()

	return setFields(ps, v, t)
}

func setFields(ps *Parameters, v reflect.Value, t reflect.Type) error {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fv := v.Field(i)

		// Walk embedded structs
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			if err := setFields(ps, fv, f.Type); err != nil {
				return err
			}
			continue
		}

		name := f.Tag.Get("param")
		if name == "" || name == "-" {
			continue
		}

		val := ps.effectiveValue(name)
		if val == nil {
			continue
		}

		if err := setField(fv, val); err != nil {
			return fmt.Errorf("bind: field %q (%s): %w", name, f.Type, err)
		}
	}
	return nil
}

// effectiveValue returns the effective value for a named parameter.
func (ps *Parameters) effectiveValue(name string) any {
	for i := range ps.params {
		if ps.params[i].Name == name {
			return ps.params[i].EffectiveValue()
		}
	}
	return nil
}

func setField(fv reflect.Value, val any) error {
	rv := reflect.ValueOf(val)

	// Direct assignment if types match
	if rv.Type().AssignableTo(fv.Type()) {
		fv.Set(rv)
		return nil
	}

	// Type coercion for common mismatches (e.g. float64 from JSON -> int)
	switch fv.Kind() {
	case reflect.Int, reflect.Int64:
		switch v := val.(type) {
		case float64:
			fv.SetInt(int64(v))
			return nil
		case string:
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}
			fv.SetInt(n)
			return nil
		}
	case reflect.String:
		fv.SetString(fmt.Sprintf("%v", val))
		return nil
	case reflect.Bool:
		switch v := val.(type) {
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return err
			}
			fv.SetBool(b)
			return nil
		default:
			_ = v
		}
	}

	return fmt.Errorf("cannot assign %T to %s", val, fv.Type())
}

func goTypeToParamType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int64:
		return "int"
	case reflect.Bool:
		return "bool"
	case reflect.Float64:
		return "float64"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.String {
			return "[]string"
		}
	}
	return "any"
}

func parseDefault(raw string, t reflect.Type) any {
	switch t.Kind() {
	case reflect.String:
		return raw
	case reflect.Int:
		v, _ := strconv.Atoi(raw)
		return v
	case reflect.Int64:
		v, _ := strconv.ParseInt(raw, 10, 64)
		return v
	case reflect.Bool:
		v, _ := strconv.ParseBool(raw)
		return v
	case reflect.Float64:
		v, _ := strconv.ParseFloat(raw, 64)
		return v
	case reflect.Slice:
		if t.Elem().Kind() == reflect.String {
			return strings.Split(raw, ",")
		}
	}
	return raw
}
