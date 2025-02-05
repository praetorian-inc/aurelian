package types

import (
	"regexp"
)

type OptionType string

const (
	String OptionType = "string"
	Bool   OptionType = "bool"
	Int    OptionType = "int"
)

type Option struct {
	Name                string
	Short               string
	Description         string
	Default             string
	Required            bool
	Type                OptionType
	Value               string
	ValueFormat         *regexp.Regexp
	ValueList           []string
	ValueCommaSeparated bool // Indicates if the value can be a comma-separated list of ValueList items
	Sensitive           bool
}
