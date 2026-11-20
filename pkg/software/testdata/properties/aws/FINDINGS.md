# Phase 0 — harvested AWS property fixtures

Source run: `go run . aws recon list-all -p default -s full` against account
`411435703965` (the `default` profile), 2026-11-20. 49 resource types across
17 regions; **260 resources** enumerated. 17 operations were skipped across
12 regions (`TypeNotFoundException`×6, `UnsupportedActionException`×11).

The fixtures beside this file are the verbatim `properties` objects from that
run, one JSON array per resource type, with values under keys matching
`password|secret|token|key` replaced by `"REDACTED"`.

---

## 1. Which tier-1 property paths are present in `ListResources` output?

| Resource type | Path the spec expects | Enumerated by `GetAll()` | Instances in account | Path present? |
|---|---|---|---|---|
| `AWS::RDS::DBInstance` | `Engine` + `EngineVersion` | yes | 0 | **unknown** — no instance |
| `AWS::RDS::DBCluster` | `Engine` + `EngineVersion` | yes | 0 | **unknown** — no instance |
| `AWS::Lambda::Function` | `Runtime` | yes | 13 | **ABSENT** |
| `AWS::EKS::Cluster` | `Version` | yes | 0 | **unknown** — no instance |
| `AWS::OpenSearchService::Domain` | `EngineVersion` | yes | 0 | **unknown** — no instance |
| `AWS::ElastiCache::CacheCluster` | `Engine` + `EngineVersion` | **no** | — | **unknown** — type not enumerated |
| `AWS::Redshift::Cluster` | `ClusterVersion` | yes | 0 | **unknown** — no instance |
| `AWS::ElasticBeanstalk::Environment` | `SolutionStackName` | yes | 0 | **unknown** — no instance |
| `AWS::MSK::Cluster` | `KafkaVersion` | **no** | — | **unknown** — type not enumerated |
| `AWS::ECS::TaskDefinition` | `ContainerDefinitions[].Image` | yes | 1 | **PRESENT** |

Two types are not reachable at all today. `AWS::ElastiCache::CacheCluster` and
`AWS::MSK::Cluster` are in neither `baseline` (`pkg/aws/resourcetypes/types.go:31`)
nor any consumer module's `SupportedResourceTypes()`, which confirms the spec's
"enumerated by nothing today" claim and the phase-2 decision to add them to
`baseline`.

### The one hard measurement: Lambda's listing is sparse

Across all 13 functions the union of property keys returned by
`ListResources` is exactly:

```
FunctionName, FunctionUrl, FunctionUrlAuthType, Role
```

`Runtime` is **not among them**, nor are `Code.ImageUri` or `PackageType`. So
**both** the tier-1 Lambda decoder (`Runtime`) and the tier-2 Lambda image
decoder (`Code.ImageUri`) will see nothing without a `GetResource`. Lambda
therefore needs `hydrateIfMissing` in phase 2 — this is measured, not assumed.

ECS is the opposite case: `ContainerDefinitions` arrives complete and inline,
with each container's `Image` populated, so tier 2 on ECS is genuinely free.

For the six types with no instance in the account, presence is **unknown**, not
"present". Their decoders ship untested against real data — see question 3.

---

## 2. What do the version values actually look like?

| Source | Sample observed | Granularity |
|---|---|---|
| `AWS::ECS::TaskDefinition` → `ContainerDefinitions[0].Image` | `alpine:latest` | no version at all |
| `AWS::Lambda::Function` → `Runtime` | *(none — key absent from the listing)* | — |
| `AWS::EKS::Cluster` → `Version` | *(none — no cluster in account)* | — |
| `AWS::OpenSearchService::Domain` → `EngineVersion` | *(none — no domain in account)* | — |

**This account does not settle "The version-granularity gap."** The three types
the spec names as the open cases — EKS, Lambda `Runtime`, OpenSearch — produced
no version sample whatsoever: two have no instances, and Lambda's `Runtime` is
absent from the sparse listing. Phase 0 was expected to answer this question
with data and cannot.

What it does show is the shape of the other half: the single real image
reference is `alpine:latest`, a tag carrying no parseable version. Under the
spec's normalisation rules that emits nothing, which is the intended behaviour
and the only end-to-end tier-2 case this account exercises.

Consequence for phase 1: the resolution rule stays as the spec writes it —
minor-only versions that no live dictionary entry carries emit nothing. There is
no measured evidence here for widening it, and the spec's anti-goal ("emitting a
confidently wrong CPE") sets the default. Revisit once tier 1 runs against an
account that actually holds EKS/RDS/OpenSearch.

---

## 3. Which types were absent from the account entirely?

Eight of the ten tier-1 types produced no fixture:

| Type | Why absent |
|---|---|
| `AWS::RDS::DBInstance` | enumerated, zero instances |
| `AWS::RDS::DBCluster` | enumerated, zero instances |
| `AWS::EKS::Cluster` | enumerated, zero instances |
| `AWS::OpenSearchService::Domain` | enumerated, zero instances |
| `AWS::Redshift::Cluster` | enumerated, zero instances |
| `AWS::ElasticBeanstalk::Environment` | enumerated, zero instances |
| `AWS::ElastiCache::CacheCluster` | **not enumerated** — in no `baseline` or module type list |
| `AWS::MSK::Cluster` | **not enumerated** — in no `baseline` or module type list |

Their decoders ship tested only against hand-written property maps derived from
the spec's table, not against observed CloudControl output. The risk this
carries is exactly the one phase 0 existed to retire: a property path read from
the CloudFormation schema rather than from live output may be spelled
differently, nested differently, or absent. **Re-run this harvest against an
account holding RDS, EKS and OpenSearch before phase 2 ships those decoders.**

Only `AWS::Lambda::Function` and `AWS::ECS::TaskDefinition` have fixtures, and
of those only ECS carries a usable tier-1/2 property.
