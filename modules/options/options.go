package options

import (
	"errors"
	"regexp"
	"strconv"
)

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

func SetRequired(option *Option, required bool) *Option {
	option.Required = required
	return option
}

func GetOptionByName(name string, options []*Option) *Option {

	for _, option := range options {
		if option.Name == name {
			return option
		}
	}

	return nil
}

// ValidateOption ensures the provided option is in the list of options and valid.
// It checks if the option is required and has a valid format.
// If any validation fails, it returns an error.
func ValidateOption(opt Option, options []*Option) error {

	for _, option := range options {
		if option.Name == opt.Name {

			// Not required and empty
			if !opt.Required && option.Value == "" {
				return nil
			}

			// Required and empty
			if opt.Required && option.Value == "" {
				return errors.New(option.Name + " is required")
			}

			if opt.ValueFormat != nil && !opt.ValueFormat.MatchString(option.Value) {
				return errors.New(option.Name + " is an invalid format")
			}

			// Check if the option value is of the correct type when non-string
			switch opt.Type {
			case Bool:
				_, err := strconv.ParseBool(option.Value)
				return err
			case Int:
				_, err := strconv.Atoi(option.Value)
				return err
			}
		}
	}

	return nil
}

func ValidateOptions(opts []*Option, required []*Option) error {
	for _, opt := range required {
		err := ValidateOption(*opt, required)
		if err != nil {
			return err
		}
	}
	return nil
}
