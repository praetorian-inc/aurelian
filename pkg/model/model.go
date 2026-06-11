// Package model defines the AurelianModel marker interface shared across all
// Aurelian output types. It lives in its own package to avoid circular imports
// between output, types, and plugin.
package model

// aurelianModelToken is an unexported type used to seal the AurelianModel interface.
// External packages cannot construct this type, so they cannot implement
// AurelianModel without embedding BaseAurelianModel.
type aurelianModelToken struct{}

// AurelianModel is a marker interface for all Aurelian output models.
// Only types that embed BaseAurelianModel can satisfy this interface.
type AurelianModel interface {
	IsAurelianModel() aurelianModelToken
}

// BaseAurelianModel is embedded into output structs to satisfy the AurelianModel interface.
type BaseAurelianModel struct{}

func (BaseAurelianModel) IsAurelianModel() aurelianModelToken { return aurelianModelToken{} }
