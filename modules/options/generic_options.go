package options

import "regexp"

var OutputOpt = Option{
	Name:        "output",
	Short:       "o",
	Description: "output directory",
	Required:    false,
	Type:        String,
	Value:       "output",
}

var FileNameOpt = Option{
	Name:        "file",
	Short:       "f",
	Description: "File name",
	Required:    false,
	Type:        String,
	Value:       "",
}

var PathOpt = Option{
	Name:        "path",
	Short:       "p",
	Description: "path to the file",
	Required:    true,
	Type:        String,
	Value:       "",
}

var UrlOpt = Option{
	Name:        "url",
	Short:       "u",
	Description: "url to the file",
	Required:    true,
	Type:        String,
	Value:       "",
}

var PromptOpt = Option{
	Name:        "prompt",
	Description: "prompt for input",
	Required:    false,
	Type:        String,
	Value:       "",
}

var ModelOpt = Option{
	Name:        "model",
	Description: "ollama model",
	Required:    false,
	Type:        String,
	Value:       "llama3",
}

var IPOpt = Option{
	Name:        "ip",
	Description: "ip address",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$`),
}
