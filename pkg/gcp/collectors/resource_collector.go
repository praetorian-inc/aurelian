package gcloudcollectors

import (
	"context"
	"fmt"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	gcperrors "github.com/praetorian-inc/nebula/pkg/gcp/errors"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type ResourceCollector struct {
	ctx           context.Context
	clientOptions []option.ClientOption
	assetClient   *asset.Client
}

func NewResourceCollector(ctx context.Context, clientOptions ...option.ClientOption) (*ResourceCollector, error) {
	collector := &ResourceCollector{
		ctx:           ctx,
		clientOptions: clientOptions,
	}
	var err error
	collector.assetClient, err = asset.NewClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create asset client: %w", err)
	}
	return collector, nil
}

func (rc *ResourceCollector) Close() error {
	if rc.assetClient != nil {
		return rc.assetClient.Close()
	}
	return nil
}

func (rc *ResourceCollector) ListResourcesInScope(scope string, assetTypes []string) ([]*gcptypes.Resource, error) {
	req := &assetpb.ListAssetsRequest{
		Parent:      scope,
		AssetTypes:  assetTypes,
		ContentType: assetpb.ContentType_RESOURCE,
	}

	it := rc.assetClient.ListAssets(rc.ctx, req)
	resources := make([]*gcptypes.Resource, 0)

	for {
		assetResp, err := gcperrors.RetryIterator(it.Next)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate assets in %s: %w", scope, err)
		}

		resource := &gcptypes.Resource{
			URI:        assetResp.Name,
			AssetType:  assetResp.AssetType,
			Name:       extractDisplayName(assetResp),
			Location:   extractLocation(assetResp),
			ParentURI:  extractParentURI(assetResp),
			Properties: make(map[string]string),
		}

		if assetResp.Resource != nil && assetResp.Resource.Data != nil {
			if labels := assetResp.Resource.Data.GetFields()["labels"]; labels != nil {
				if labelsStruct := labels.GetStructValue(); labelsStruct != nil {
					for key, val := range labelsStruct.Fields {
						resource.Properties[key] = val.GetStringValue()
					}
				}
			}
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func (rc *ResourceCollector) ListResourcesWithPolicies(scope string, assetTypes []string) ([]*gcptypes.Resource, error) {
	req := &assetpb.ListAssetsRequest{
		Parent:      scope,
		AssetTypes:  assetTypes,
		ContentType: assetpb.ContentType_IAM_POLICY,
	}

	it := rc.assetClient.ListAssets(rc.ctx, req)
	resources := make([]*gcptypes.Resource, 0)

	for {
		assetResp, err := gcperrors.RetryIterator(it.Next)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate assets with policies in %s: %w", scope, err)
		}

		resource := &gcptypes.Resource{
			URI:        assetResp.Name,
			AssetType:  assetResp.AssetType,
			Name:       extractDisplayName(assetResp),
			Location:   extractLocation(assetResp),
			ParentURI:  extractParentURI(assetResp),
			Properties: make(map[string]string),
		}

		if assetResp.IamPolicy != nil {
			resource.Policies.Allow = convertIAMPolicy(assetResp.IamPolicy, assetResp.Name)
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func extractDisplayName(asset *assetpb.Asset) string {
	if asset.Resource != nil && asset.Resource.Data != nil {
		if name := asset.Resource.Data.GetFields()["name"]; name != nil {
			return name.GetStringValue()
		}
		if displayName := asset.Resource.Data.GetFields()["displayName"]; displayName != nil {
			return displayName.GetStringValue()
		}
	}
	return ""
}

func extractLocation(asset *assetpb.Asset) string {
	if asset.Resource != nil && asset.Resource.Location != "" {
		return asset.Resource.Location
	}
	return ""
}

func extractParentURI(asset *assetpb.Asset) string {
	if asset.Resource != nil && asset.Resource.Parent != "" {
		return asset.Resource.Parent
	}
	return ""
}

func convertIAMPolicy(policy *iampb.Policy, resourceURI string) *gcptypes.AllowPolicy {
	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: resourceURI,
		Version:     int(policy.Version),
		Etag:        string(policy.Etag),
		Bindings:    make([]gcptypes.AllowBinding, 0),
	}

	for _, binding := range policy.Bindings {
		allowBinding := gcptypes.AllowBinding{
			Role:    binding.Role,
			Members: binding.Members,
		}

		if binding.Condition != nil {
			allowBinding.Condition = &gcptypes.Condition{
				Title:       binding.Condition.Title,
				Description: binding.Condition.Description,
				Expression:  binding.Condition.Expression,
			}
		}

		allowPolicy.Bindings = append(allowPolicy.Bindings, allowBinding)
	}

	return allowPolicy
}
