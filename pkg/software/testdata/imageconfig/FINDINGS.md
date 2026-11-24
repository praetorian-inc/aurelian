# Harvested image configs — observed markers

Harvested 2026-11-24 from the live registries, linux/amd64. Each `<slug>.json`
holds `{image, digest, config}` with the config blob verbatim. `_harvest.json`
is the index.

**This file is the input to the marker table in `pkg/software/imagestack.go`.**
Do not write that table from memory or from the plan's examples — every row
below was observed.

## Markers that map to a product

Resolution measured against the committed `pkg/cpe/cpemap.json.gz`.
"truncated→X" means the observed version has no dictionary entry but X does.

| Marker env | Product | Observed value | Normalised | Resolves |
|---|---|---|---|---|
| `NGINX_VERSION` | `nginx` | `1.25.5` | `1.25.5` | exact → `f5:nginx` |
| `HTTPD_VERSION` | `http_server` | `2.4.71` | `2.4.71` | exact → `apache:http_server` |
| `HAPROXY_VERSION` | `haproxy` | `2.9.15` | `2.9.15` | exact → `haproxy:haproxy` |
| `TOMCAT_VERSION` | `tomcat` | `10.1.62` | `10.1.62` | exact → `apache:tomcat` |
| `RUBY_VERSION` | `ruby` | `3.3.14` | `3.3.14` | exact → `ruby-lang:ruby` |
| `PHP_VERSION` | `php` | `8.3.37`, `8.2.31` | same | exact → `php:php` |
| `GOLANG_VERSION` | `go` | `1.23.12` | `1.23.12` | exact → `golang:go` |
| `DOTNET_VERSION` | `.net` | `8.0.34` | `8.0.34` | exact → `microsoft:.net` |
| `PYTHON_VERSION` | `python` | `3.11.18` | `3.11.18` | truncated→`3.11` → `python:python` |
| `NODE_VERSION` | `node.js` | `20.20.2` | `20.20.2` | truncated→`20.20` → `nodejs:node.js` |
| `REDIS_VERSION` | `redis` | `7.4.12` | `7.4.12` | truncated→`7.4` → `redis:redis` |
| `MEMCACHED_VERSION` | `memcached` | `1.6.45` | `1.6.45` | truncated→`1.6` → `memcached:memcached` |
| `MONGO_VERSION` | `mongodb` | `7.0.48` | `7.0.48` | truncated→`7.0` → `mongodb:mongodb` |
| `MYSQL_VERSION` | `mysql` | `8.4.13.1-1.el9` | `8.4.13.1` | truncated→`8.4` → `oracle:mysql` |
| `JENKINS_VERSION` | `jenkins` | `2.580.2` | `2.580.2` | truncated→`2.580` → `jenkins:jenkins` |
| `JAVA_VERSION` | `openjdk` | `jdk-25.0.5.1+2`, `jdk-17.0.21.1+2` | **`""`** | none — normalisation gap, see below |
| `MARIADB_VERSION` | `mariadb` | `1:11.8.9+maria~ubu2404` | **`""`** | none — normalisation gap, see below |
| `PG_VERSION` | `postgresql` | `15.20-1.pgdg13+1` | `15.20` | only at bare major `15` — **rejected**, see below |
| `RABBITMQ_VERSION` | `rabbitmq` | `3.13.7` | `3.13.7` | only at bare major `3` — **rejected**, see below |
| `INFLUXDB_VERSION` | `influxdb` | `2.7.12` | `2.7.12` | only at bare major `2` — **rejected**, see below |

## Two normalisation gaps found by this harvest

`NormalizeVersion` requires a leading digit after an optional `v`, and rejects
any value containing a colon. Two real marker values are lost to that:

- `JAVA_VERSION=jdk-25.0.5.1+2` — the `jdk-` distribution prefix.
  `cpe.Resolve("openjdk", "25.0.5.1")` **does** resolve to `oracle:openjdk`, so
  this is a pure normalisation miss costing a real emission.
- `MARIADB_VERSION=1:11.8.9+maria~ubu2404` — a Debian **epoch** (`1:`). The
  colon rule exists to distrust digests and compound identifiers, and it is
  right to; an epoch is a different, well-defined thing.

Both are fixed in `pkg/cpe/version.go`. The leading-digit rule itself is not
relaxed — it is what stops `latest`, `alpine` and `stable` becoming versions.

## Why the fallback floors at major.minor

A naive walk to the bare major fabricates inventory. Measured:

```
rabbitmq 3.13.7 -> 3.13 (no entry) -> 3  => [broadcom:rabbitmq:3, voxpupuli:rabbitmq:3]
influxdb 2.7.12 -> 2.7  (no entry) -> 2  => [influxdata:influxdb:2]
```

`voxpupuli` is a **Puppet module**, not RabbitMQ, and it is already named in
`test/terraform/aws/recon/technology-emission/outputs.tf`'s
`forbidden_cpe_substrings` as an anti-goal. That fixture's own comment predicts
this exactly: the homonym sibling policy is safe only because homonyms are
"capped at a version from 2004-2018 that will not appear in a container tag",
and "a resolution rule loosened to reach homonyms would fabricate inventory".

Truncating to a bare major is precisely that loosening. So the walk floors at
two dotted components.

The cost is products whose dictionary versions *are* bare majors — PostgreSQL
`15`, InfluxDB `2`. Those are not lost: tier 2 already reads them from the image
tag (`postgres:15` → `15` → `postgresql:postgresql:15`), which is pinned in the
existing integration fixture. The two tiers are complementary — the tag covers
coarse-versioned products, the config marker covers patch-versioned ones.

## `*_VERSION` env vars that must NOT map to a product

The reason the marker table is an allowlist and not a `*_VERSION` sweep. Every
one of these was observed sitting beside a real marker:

| Env var | Seen on | What it actually is |
|---|---|---|
| `GOSU_VERSION` | postgres, mysql, mariadb, mongo | the `gosu` setuid helper |
| `NJS_VERSION` | nginx | the njs scripting module, not nginx |
| `YARN_VERSION` | node | the Yarn package manager |
| `MYSQL_SHELL_VERSION` | mysql | the client shell, not the server |
| `JSYAML_VERSION` | mongo | a bundled JS YAML library |
| `INFLUX_CLI_VERSION` | influxdb | the CLI, not the server |
| `VERSION` (empty) | hashicorp/vault | a bare, unset build arg |

## Images carrying no usable marker

`traefik`, `consul`, `grafana/grafana`, `confluentinc/cp-kafka`,
`opensearchproject/opensearch`, and every `public.ecr.aws/lambda/*` base except
`dotnet`. These fall back to tier 2's tag parsing, which is the designed
degradation — the config fetch costs nothing extra for them because it is the
same request either way.

## Fetch failure

`library/openjdk` — Docker Hub returns an error for every tag; the official
`openjdk` image is deprecated and withdrawn. `eclipse-temurin` is its successor
and carries the same `JAVA_VERSION` marker, so the openjdk row above is sourced
from `eclipse-temurin:17-jre` and `tomcat:10` instead.
