package cloudfront

// Finding pairs a vulnerable distribution with its associated Route53 records.
type Finding struct {
	VulnerableDistribution
	Route53Records []Route53Record
}

// DistributionInfo contains information about a CloudFront distribution.
type DistributionInfo struct {
	ID         string
	DomainName string
	Aliases    []string
	AccountID  string
	Origins    []OriginInfo
}

// OriginInfo contains information about a CloudFront origin.
type OriginInfo struct {
	ID         string
	DomainName string
	OriginType string // "s3" or "custom"
}

// VulnerableDistribution describes a CloudFront distribution with a missing S3 origin bucket.
type VulnerableDistribution struct {
	DistributionID     string
	DistributionDomain string
	Aliases            []string
	MissingBucket      string
	OriginDomain       string
	OriginID           string
	AccountID          string
}

// Route53Record describes a DNS record pointing to a CloudFront distribution.
type Route53Record struct {
	ZoneID     string
	ZoneName   string
	RecordName string
	RecordType string
	Value      string
}

// BucketExistence represents the result of a bucket existence check.
type BucketExistence int

const (
	BucketExists BucketExistence = iota
	BucketNotExists
	BucketUnknown
)
