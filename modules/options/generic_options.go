package options

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
	Type:        Bool,
	Value:       "",
}
