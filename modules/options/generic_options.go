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
	Description: "path to the file",
	Required:    true,
	Type:        String,
	Value:       "",
}
