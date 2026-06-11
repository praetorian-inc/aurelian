// Package model defines the AurelianModel marker interface shared across all
// Aurelian output types. It lives in its own package to avoid circular imports
// between output, types, and plugin.
package model

// aurelianModelToken is an unexported type historically used to seal the
// AurelianModel interface. AurelianModel is now an open (empty) interface, so
// any type satisfies it and embedding BaseAurelianModel is no longer required.
// This token — and the BaseAurelianModel.IsAurelianModel() helper that returns
// it — are retained only as source-compatibility markers for existing
// embedders, not as an enforcement mechanism.
type aurelianModelToken struct{}

// AurelianModel is the marker type for Aurelian output models. It is an open
// interface so platform types such as capmodel.Risk — external generated
// structs we cannot attach methods to — can be emitted through the module
// pipeline directly, without an Aurelian-side wrapper.
type AurelianModel interface{}

// BaseAurelianModel is embedded into output structs to satisfy the AurelianModel interface.
type BaseAurelianModel struct{}

func (BaseAurelianModel) IsAurelianModel() aurelianModelToken { return aurelianModelToken{} }
