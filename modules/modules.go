package modules

import (
	"github.com/praetorian-inc/nebula/modules/options"
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

func (m *BaseModule) MakeResult(data interface{}) Result {
	return Result{
		Platform: m.Platform,
		Module:   m.Name,
		Data:     data,
	}
}
