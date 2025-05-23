package analyze

// func init() {
// 	// Register the AWS policy diff module
// 	registry.Register("aws", "analyze", "diff-policies", *AWSPolicyDiff)
// }

// var AWSPolicyDiff = chain.NewModule(
// 	cfg.NewMetadata(
// 		"AWS Policy Diff",
// 		"Compare two AWS policies and find differences",
// 	).WithProperties(map[string]any{
// 		"platform": "aws",
// 		"authors":  []string{"Praetorian"},
// 	}).WithChainInputParam(
// 		"file1",
// 	),
// ).WithLinks(
// 	aws.NewAWSPolicyDiff,
// 	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
// ).WithOutputters(
// 	output.NewJSONOutputter,
// 	output.NewConsoleOutputter,
// ).WithInputParam(
// 	options.AwsPolicyDiffInput().WithDefault([]string{"all"}),
// )
