package options

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain/cfg"
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

// JanusParamAdapter converts Janus parameter definitions to legacy options format using default values.
// This function only uses the default values from parameter definitions.
// For runtime values, use JanusArgsAdapter instead.
func JanusParamAdapter(params []cfg.Param) []*types.Option {
	options := make([]*types.Option, len(params))
	for i, param := range params {
		options[i] = &types.Option{
			Name:        param.Name(),
			Description: param.Description(),
			Required:    param.Required(),
		}

		switch param.Type() {
		case "string":
			options[i].Value = param.Value().(string)
			options[i].Type = types.String
		case "int":
			options[i].Value = strconv.Itoa(param.Value().(int))
			options[i].Type = types.Int
		case "bool":
			options[i].Value = strconv.FormatBool(param.Value().(bool))
			options[i].Type = types.Bool
		case "[]string":
			options[i].Value = strings.Join(param.Value().([]string), ",")
			options[i].Type = types.String
		default:
			options[i].Value = param.Value().(string)
			options[i].Type = types.String

		}

	}

	return options
}

// JanusArgsAdapter converts runtime Janus arguments to legacy options format.
// This function uses the actual runtime values that were passed via command line flags.
// It takes both the parameter definitions and the runtime arguments map.
func JanusArgsAdapter(params []cfg.Param, args map[string]any) []*types.Option {
	options := make([]*types.Option, len(params))
	for i, param := range params {
		options[i] = &types.Option{
			Name:        param.Name(),
			Description: param.Description(),
			Required:    param.Required(),
		}

		// Get the runtime value from args, fall back to default if not present
		var runtimeValue any
		if val, exists := args[param.Name()]; exists {
			runtimeValue = val
		} else {
			runtimeValue = param.Value()
		}

		switch param.Type() {
		case "string":
			if runtimeValue != nil {
				options[i].Value = runtimeValue.(string)
			} else {
				options[i].Value = ""
			}
			options[i].Type = types.String
		case "int":
			if runtimeValue != nil {
				options[i].Value = strconv.Itoa(runtimeValue.(int))
			} else {
				options[i].Value = "0"
			}
			options[i].Type = types.Int
		case "bool":
			if runtimeValue != nil {
				options[i].Value = strconv.FormatBool(runtimeValue.(bool))
			} else {
				options[i].Value = "false"
			}
			options[i].Type = types.Bool
		case "[]string":
			if runtimeValue != nil {
				if slice, ok := runtimeValue.([]string); ok {
					options[i].Value = strings.Join(slice, ",")
				} else {
					options[i].Value = ""
				}
			} else {
				options[i].Value = ""
			}
			options[i].Type = types.String
		default:
			if runtimeValue != nil {
				options[i].Value = fmt.Sprintf("%v", runtimeValue)
			} else {
				options[i].Value = ""
			}
			options[i].Type = types.String
		}
	}

	return options
}
