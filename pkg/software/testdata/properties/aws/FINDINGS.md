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

Consequence for phase 1: the resolution rule stays as the spec writes it. There
is no measured evidence here for widening it, and the spec's anti-goal
("emitting a confidently wrong CPE") sets the default. Revisit once tier 1 runs
against an account that actually holds EKS/RDS/OpenSearch.

### What "the rule stays as the spec writes it" actually does

The gap is **not** resolved uniformly, and an earlier draft of this document
said it was. A minor-only version is dropped for a product with several vendors
(rule 3) and *accepted* for a product with exactly one (rule 2), because rule 2
takes the sole vendor whatever the version. So the open question is already
answered — inconsistently, in whichever direction the vendor count falls.

Measured end-to-end through `Detect`, against values AWS actually produces:

| Type | Input | Emits |
|---|---|---|
| `AWS::EKS::Cluster` | `1.29` **and** `1.29.0` | nothing, ever (`kubernetes` has 2 vendors) |
| `AWS::OpenSearchService::Domain` | `OpenSearch_2.11`, `Elasticsearch_7.10` | nothing, ever |
| `AWS::Redshift::Cluster` | any | nothing, ever (NVD has no `redshift` product) |
| `AWS::Lambda::Function` | `python3.12`, `nodejs20.x`, `go1.x` | nothing |
| `AWS::Lambda::Function` | `java21`, `dotnet8`, `ruby3.2` | `oracle:openjdk:21`, `microsoft:.net:8`, `ruby-lang:ruby:3.2` |
| `AWS::ElasticBeanstalk::Environment` | `running Python 3.11` | nothing |
| `AWS::ElasticBeanstalk::Environment` | `running PHP 8.1`, `running Ruby 3.2` | `php:php:8.1`, `ruby-lang:ruby:3.2` |
| `AWS::RDS::*`, `AWS::MSK::Cluster`, `AWS::ElastiCache::*` | patch-level versions | emits normally |

**Three of the ten tier-1 types are dead and two more are half-dead.** That is
the number the phase-2 decision should be made against, and it is a stronger
argument for revisiting the rule than anything in the original spec. The
emissions rule 2 does produce (`php:php:8.1`) name the right vendor and product
but carry a version no dictionary entry has, so guard's matcher may resolve them
to no CVEs — a spurious-but-harmless node rather than a wrong one.

Pinned by `TestDetect_Tier1CoverageAgainstRealAWSValues`, so a change to the
resolution rule shows up as a diff in that test rather than as a silent change
in customer inventory.

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
