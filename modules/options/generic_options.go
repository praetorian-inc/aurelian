package options

var OutputOpt = Option{
	Name:        "output",
	Short:       "o",
	Description: "output directory",
	Required:    false,
	Type:        String,
	Value:       "output",
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
