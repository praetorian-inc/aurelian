// Package model defines the AurelianModel marker interface shared across all
// Aurelian output types. It lives in its own package to avoid circular imports
// between output, types, and plugin.
package model

// aurelianModelToken is an unexported type used to seal the AurelianModel interface.
// External packages cannot construct this type, so they cannot implement
// AurelianModel without embedding BaseAurelianModel.
type aurelianModelToken struct{}

// AurelianModel is the marker type for Aurelian output models. It is an open
// interface so platform types such as capmodel.Risk — external generated
// structs we cannot attach methods to — can be emitted through the module
// pipeline directly, without an Aurelian-side wrapper.
type AurelianModel interface{}

// BaseAurelianModel is embedded into output structs to satisfy the AurelianModel interface.
type BaseAurelianModel struct{}

func (BaseAurelianModel) IsAurelianModel() aurelianModelToken { return aurelianModelToken{} }
