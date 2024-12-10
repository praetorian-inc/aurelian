package types

// ResourceType provides a struct to help with ARN construction
type ResourceType struct {
	Service    string
	Resource   string
	Identifier string
}
