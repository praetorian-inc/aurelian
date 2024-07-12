package modules

import (
	"errors"
	"strconv"

	"github.com/praetorian-inc/nebula/modules/options"
	o "github.com/praetorian-inc/nebula/modules/options"
)

/*
func registerPackageFunctions(pkgName string, registry map[string]func(model.Job) model.Capability) {
	pkg, _ := reflect.TypeOf(model.Job{}).PkgPath(), Package(pkgName)
	funcs := runtime.FuncForPC(pkg).Name()
	for _, f := range funcs {
		if _, ok := registry[f]; !ok {
			registry[f] = pkgName
		}
	}
}
*/

type OpsecLevel string

const (
	Stealth  OpsecLevel = "stealth"
	Moderate OpsecLevel = "moderate"
	None     OpsecLevel = "none"
)

type Platform string

func GetPlatformFromString(platform string) Platform {
	switch platform {
	case "aws":
		return AWS
	case "azure":
		return Azure
	case "gcp":
		return GCP
	case "oci":
		return OCI
	case "universal":
		return Universal
	default:
		return ""
	}
}

const (
	AWS       Platform = "aws"
	Azure     Platform = "azure"
	GCP       Platform = "gcp"
	OCI       Platform = "oci"
	Universal Platform = "universal"
)

type Metadata struct {
	Id          string
	Name        string
	Description string
	Platform    Platform
	Authors     []string
	References  []string
	OpsecLevel  OpsecLevel
}

type Module interface {
	Invoke() error
}

type Run struct {
	Data chan Result
}

type BaseModule struct {
	Module
	Metadata
	Options []*options.Option
	Run     Run
}

func (m *BaseModule) Invoke() error {
	panic("not implemented")
}

func (m *BaseModule) GetOptionByName(name string) *options.Option {
	return options.GetOptionByName(name, m.Options)
}

func (m *BaseModule) AddOption(option options.Option) {
	m.Options = append(m.Options, &option)
}

func (m *BaseModule) SetMetdata(meta Metadata) {
	m.Id = meta.Id
	m.Name = meta.Name
	m.Description = meta.Description
	m.Platform = meta.Platform
	m.Authors = meta.Authors
	m.References = meta.References
	m.OpsecLevel = meta.OpsecLevel
}

// ValidateOptions ensures the provided option is in the list of options and valid.
// It checks if the option is required and has a valid format.
// If any validation fails, it returns an error.
func (m *BaseModule) ValidateOptions(opt options.Option, options []*options.Option) error {

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
			case o.Bool:
				_, err := strconv.ParseBool(option.Value)
				return err
			case o.Int:
				_, err := strconv.Atoi(option.Value)
				return err
			}
		}
	}

	return nil
}

func (m *BaseModule) MakeResult(data interface{}) Result {
	return Result{
		Platform: m.Platform,
		Module:   m.Name,
		Data:     data,
	}
}
