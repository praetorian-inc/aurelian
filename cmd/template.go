package cmd

import (
	"os"
	"strings"
	"text/template"
	"unicode"

	"github.com/spf13/cobra"
)

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Generate a module template",
	Run: func(cmd *cobra.Command, args []string) {

		cat := cmd.Flag("category").Value.String()
		provider := cmd.Flag("provider").Value.String()
		name := cmd.Flag("name").Value.String()

		funcMap := template.FuncMap{
			"toUpper":    strings.ToUpper,
			"toLower":    strings.ToLower,
			"capitalize": capitalize,
		}

		modTmpl, err := template.New("module").Funcs(funcMap).Parse(moduleTemplate)
		if err != nil {
			panic(err)
		}

		data := struct {
			Category string
			Provider string
			Name     string
		}{
			Category: cat,
			Provider: provider,
			Name:     name,
		}

		err = modTmpl.ExecuteTemplate(os.Stdout, "module", data)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	templateCmd.Flags().StringP("category", "c", "", "Category the provider for the module template")
	templateCmd.MarkFlagRequired("category")
	templateCmd.Flags().StringP("provider", "p", "", "Specify the provider for the module template")
	templateCmd.MarkFlagRequired("provider")
	templateCmd.Flags().StringP("name", "n", "", "Specify the name for the module template")
	templateCmd.MarkFlagRequired("name")

	rootCmd.AddCommand(templateCmd)
}

var moduleTemplate = `
package {{ .Category }}

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/modules"
)

/*
Add the follwoing to the init() function in cmd/registry.go to register the module:

RegisterModule({{ .Provider | toLower}}{{ .Category | capitalize}}Cmd, {{ .Category | toLower }}.{{ .Provider | capitalize}}{{ .Name }}Metadata, {{ .Category | toLower }}.{{ .Provider | capitalize}}{{ .Name }}RequiredOptions, {{ .Provider | toLower}}CommonOptions, {{ .Category | toLower}}.New{{.Provider | capitalize}}{{ .Name }})
*/

type {{ .Provider | capitalize}}{{ .Name }} struct {{ "{" }}
	modules.BaseModule
{{ "}" }}

var {{ .Provider | capitalize}}{{ .Name }}Options= []*options.Option{{ "{" }}
	&options.AwsActionOpt,
{{ "}" }}

var {{ .Provider | capitalize}}{{ .Name }}OutputProvders = []func(options []*options.Option) modules.OutputProvider{{ "{" }}
	op.NewConsoleProvider,
{{ "}" }}

var {{ .Provider | capitalize}}{{ .Name }}Metadata = modules.Metadata{{ "{" }}
	Id:          "{{ .Name | toLower }}", // this will be the CLI command name
	Name:        "{{ .Name }}",
	Description: "TODO",
	Platform:    modules.{{ .Provider | toUpper}},
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
{{ "}" }}

func New{{ .Provider | capitalize}}{{ .Name }}(options []*options.Option, run modules.Run) (modules.Module, error) {{ "{" }}
	var m {{ .Provider |capitalize}}{{ .Name }}
	m.SetMetdata({{ .Provider | capitalize}}{{ .Name }}Metadata)
	m.Run = run
	m.Options = options
	m.ConfigureOutputProviders({{ .Provider | capitalize}}{{ .Name }}OutputProvders)

	return &m, nil
{{ "}" }}

func (m *{{ .Provider | capitalize}}{{ .Name }}) Invoke() error {{ "{" }}
	defer close(m.Run.Data)

	// Do Work
	var result = "TODO"
	m.Run.Data <- m.MakeResult(result)

	return nil
{{ "}" }}
`

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
