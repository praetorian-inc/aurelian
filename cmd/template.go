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
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

/*
Add the following to the init() function in cmd/registry.go to register the module:

RegisterModule({{ .Provider | toLower}}{{ .Category | capitalize}}Cmd, {{ .Category | toLower }}.{{ .Provider | capitalize}}{{ .Name }}Metadata, {{ .Category | toLower }}.{{ .Provider | capitalize}}{{ .Name }}Options, {{ .Provider | toLower}}CommonOptions, {{ .Category }}.{{ .Provider | capitalize}}{{ .Name }}OutputProviders, {{ .Category | toLower}}.New{{.Provider | capitalize}}{{ .Name }})
*/

type {{ .Provider | capitalize}}{{ .Name }} struct {{ "{" }}
	modules.BaseModule
{{ "}" }}

var {{ .Provider | capitalize}}{{ .Name }}Options= []*types.Option{{ "{" }}{{ "}" }}

var {{ .Provider | capitalize}}{{ .Name }}OutputProviders = []func(options []*types.Option) types.OutputProvider{{ "{" }}
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

func New{{ .Provider | capitalize}}{{ .Name }}(options []*types.Option) (<-chan string, stages.Stage[string, string], error) {{ "{" }}
	pipeline, err := stages.ChainStages[string, string](
		stages.Echo[string],
	)

	if err != nil {{ "{" }}
		return nil, nil, err
	{{ "}" }}

	return stages.Generator([]string{{ "{" }}"TODO"{{ "}" }}), pipeline, nil
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
