package options

import "regexp"

type OptionType string

const (
	String OptionType = "string"
	Bool   OptionType = "bool"
	Int    OptionType = "int"
)

type Option struct {
	Name        string
	Short       string
	Description string
	Default     string
	Required    bool
	Type        OptionType
	Value       string
	ValueFormat *regexp.Regexp
	Sensitive   bool
}

func GetOptionByName(name string, options []*Option) *Option {

	for _, option := range options {
		if option.Name == name {
			return option
		}
	}

	return nil
}
