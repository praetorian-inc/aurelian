package options

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func WithRequired(option types.Option, required bool) *types.Option {
	option.Required = required
	return &option
}

func WithDefaultValue(option types.Option, value string) *types.Option {
	option.Value = value
	return &option
}

func WithDescription(option types.Option, description string) *types.Option {
	option.Description = description
	return &option
}

func GetOptionByName(name string, options []*types.Option) *types.Option {

	for _, option := range options {
		if option.Name == name {
			return option
		}
	}
	return nil
}

func CreateDeepCopyOfOptions(original []*types.Option) []*types.Option {
	copiedOptions := make([]*types.Option, len(original))

	for i, option := range original {
		newOption := *option
		copiedOptions[i] = &newOption
	}

	return copiedOptions
}

// ValidateOption ensures the provided option is in the list of options and valid.
// It checks if the option is required and has a valid format.
// If any validation fails, it returns an error.
func ValidateOption(opt types.Option, options []*types.Option) error {

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

			if opt.ValueList != nil {
				values := strings.Split(option.Value, ",")
				for _, value := range values {
					value = strings.TrimSpace(value)
					valid := false
					for _, allowedValue := range opt.ValueList {
						if strings.EqualFold(value, allowedValue) {
							valid = true
							break
						}
					}
					if !valid {
						return fmt.Errorf("%s contains invalid value '%s'. Valid options are: %s",
							opt.Name,
							value,
							strings.Join(opt.ValueList, ", "))
					}
				}
				return nil
			}

			// Check if the option value is of the correct type when non-string
			switch opt.Type {
			case types.Bool:
				_, err := strconv.ParseBool(option.Value)
				return err
			case types.Int:
				_, err := strconv.Atoi(option.Value)
				return err
			}
		}
	}

	return nil
}

func ValidateOptions(opts []*types.Option, required []*types.Option) error {
	for _, opt := range required {
		err := ValidateOption(*opt, required)
		if err != nil {
			return err
		}
	}
	return nil
}
