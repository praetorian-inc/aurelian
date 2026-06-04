package dnstakeover

import (
	"context"
	"net"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Route53Record represents a single DNS record from a public hosted zone.
type Route53Record struct {
	ZoneID     string
	ZoneName   string
	RecordName string
	Type       string   // "CNAME", "A", "NS", etc.
	Values     []string // CNAME targets, IPs, or nameservers
	IsAlias    bool
}

// eipCache holds lazily-initialized EIP state scoped to a single checker run.
type eipCache struct {
	once         sync.Once
	ranges       []parsedPrefix
	allocatedIPs map[string]bool
	err          error
}

type parsedPrefix struct {
	network *net.IPNet
	region  string
	service string
}

// CheckContext holds shared state for checker functions.
type CheckContext struct {
	Ctx       context.Context
	Opts      plugin.AWSCommonRecon
	AccountID string
	EIPCache  *eipCache
}
