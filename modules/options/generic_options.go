package options

import (
	"regexp"

	"github.com/praetorian-inc/nebula/pkg/types"
)

var OutputOpt = types.Option{
	Name:        "output",
	Short:       "o",
	Description: "output directory",
	Required:    false,
	Type:        types.String,
	Value:       "output",
}

var FileNameOpt = types.Option{
	Name:        "file",
	Short:       "f",
	Description: "File name",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var PathOpt = types.Option{
	Name:        "path",
	Short:       "p",
	Description: "path to the file",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var UrlOpt = types.Option{
	Name:        "url",
	Short:       "u",
	Description: "url to the file",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var PromptOpt = types.Option{
	Name:        "prompt",
	Description: "prompt for input",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var ModelOpt = types.Option{
	Name:        "model",
	Description: "ollama model",
	Required:    false,
	Type:        types.String,
	Value:       "llama3",
}

var IPOpt = types.Option{
	Name:        "ip",
	Description: "ip address",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$`),
}

var JqFilterOpt = types.Option{
	Name:        "jq",
	Description: "jq filter",
	Required:    false,
	Type:        types.String,
	Value:       "",
}
