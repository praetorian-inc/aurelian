package utils

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	u "github.com/mpvl/unique"
)

var serviceDim = string(types.DimensionService)
var regionDim = string(types.DimensionRegion)

func GetRegionsInUse(cfg aws.Config) ([]string, error) {
	groupBy := []types.GroupDefinition{
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  &regionDim,
		},
	}
	res, err := getCostByService(cfg, groupBy, nil, true)
	if err != nil {
		return nil, err
	}

	return outputToSlice(res, true), nil
}

func GetServicesInUse(cfg aws.Config) ([]string, error) {
	groupBy := []types.GroupDefinition{
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  &serviceDim,
		},
	}
	res, err := getCostByService(cfg, groupBy, nil, true)
	if err != nil {
		return nil, err
	}

	return outputToSlice(res, true), nil
}

func GetRegionsUsedByService(cfg aws.Config, service []string) ([]string, error) {
	filter := &types.Expression{
		Dimensions: &types.DimensionValues{
			Key:    types.DimensionService,
			Values: service,
		},
	}
	groupBy := []types.GroupDefinition{
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  &regionDim,
		},
	}
	resp, err := getCostByService(cfg, groupBy, filter, true)
	if err != nil {
		return nil, err
	}

	return outputToSlice(resp, true), nil
}

func GetServiceAndRegions(cfg aws.Config) (map[string][]string, error) {
	groupBy := []types.GroupDefinition{
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  &serviceDim,
		},
		{
			Type: types.GroupDefinitionTypeDimension,
			Key:  &regionDim,
		},
	}
	resources, err := getCostByService(cfg, groupBy, nil, false)
	if err != nil {
		return nil, err
	}

	//fmt.Println(resources)

	serviceRegionMap := make(map[string][]string)
	for _, res := range resources.ResultsByTime {
		for _, group := range res.Groups {
			service := group.Keys[0]
			region := group.Keys[1]

			amount := group.Metrics[string(types.MetricBlendedCost)].Amount
			zero := "0"
			if amount == &zero {

				continue
			}

			if _, ok := serviceRegionMap[service]; !ok {
				serviceRegionMap[service] = []string{}
			}
			serviceRegionMap[service] = append(serviceRegionMap[service], region)
		}
	}

	// Unique the regions slice
	for service, regions := range serviceRegionMap {
		r := u.StringSlice{P: &regions}
		u.Sort(r)
		u.Strings(r.P)
		serviceRegionMap[service] = *r.P
	}

	return serviceRegionMap, nil
}

func getCostByService(cfg aws.Config, groupBy []types.GroupDefinition, filter *types.Expression, unique bool) (*costexplorer.GetCostAndUsageOutput, error) {
	client := costexplorer.NewFromConfig(cfg)

	start := time.Now().AddDate(0, -2, 0).Format("2006-01-02")
	end := time.Now().Format("2006-01-02")

	params := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &types.DateInterval{
			Start: &start,
			End:   &end,
		},
		Granularity: types.GranularityMonthly,
		Metrics:     []string{string(types.MetricBlendedCost)},
		GroupBy:     groupBy,
	}

	if filter != nil {
		params.Filter = filter
	}

	resp, err := client.GetCostAndUsage(context.TODO(), params)
	if err != nil {
		return nil, err
	}

	// TODO: filter services where the cost is 0
	/*
		jqFilter := ".ResultsByTime[].Groups[] | select(.Metrics.BlendedCost.Amount | tonumber > 0)"
		respBytes, err := jq.PerformJqQuery(resp, jqFilter)
	*/

	return resp, err
}

func outputToSlice(output *costexplorer.GetCostAndUsageOutput, unique bool) []string {
	var resources []string

	for _, resource := range output.ResultsByTime {
		for _, group := range resource.Groups {
			resources = append(resources, group.Keys...)
		}
	}

	if unique {
		r := u.StringSlice{P: &resources}
		u.Sort(r)
		u.Strings(r.P)
		resources = *r.P
	}
	return resources
}
