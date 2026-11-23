# The expected CPE strings below are written by hand, not derived from the code
# under test. That is the point: a test that computed them by calling
# software.Detect would compare the system to itself and pass no matter what the
# decoder emitted. These literals are the contract.
#
# Each resource gets two outputs — an identifier the test matches on, and the
# exact CPE set that resource must emit. An empty list means "must emit
# nothing", which is an assertion, not an absence of one.

output "test_regions" {
  value = [var.region]
}

# --- Tier 2: ECS container images -------------------------------------------

output "taskdef_controls_family" {
  value = aws_ecs_task_definition.controls.family
}

# nginx:1.25.3 -> live vendor f5. alpine:3.19 -> nothing.
output "expected_controls_cpes" {
  value = ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"]
}

output "taskdef_parsing_family" {
  value = aws_ecs_task_definition.parsing.family
}

# Four images, three CPEs: registry-qualified postgres, httpd -> http_server,
# nginx with a variant-suffixed tag. nginx:latest -> nothing.
output "expected_parsing_cpes" {
  value = [
    "cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
  ]
}

output "taskdef_siblings_family" {
  value = aws_ecs_task_definition.siblings.family
}

# redis:6.2.6 cannot choose between two live vendors and emits both. Pinned so
# that narrowing this later surfaces as a test diff, not a silent change.
output "expected_siblings_cpes" {
  value = [
    "cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*",
    "cpe:2.3:a:redislabs:redis:6.2.6:*:*:*:*:*:*:*",
  ]
}

# --- Tier 1: Lambda runtimes ------------------------------------------------

output "lambda_java_name" {
  value = aws_lambda_function.runtime["java"].function_name
}

output "expected_lambda_java_cpes" {
  value = ["cpe:2.3:a:oracle:openjdk:21:*:*:*:*:*:*:*"]
}

output "lambda_ruby_name" {
  value = aws_lambda_function.runtime["ruby"].function_name
}

output "expected_lambda_ruby_cpes" {
  value = ["cpe:2.3:a:ruby-lang:ruby:3.2:*:*:*:*:*:*:*"]
}

output "lambda_dotnet_name" {
  value = aws_lambda_function.runtime["dotnet"].function_name
}

output "expected_lambda_dotnet_cpes" {
  value = ["cpe:2.3:a:microsoft:.net:8:*:*:*:*:*:*:*"]
}

output "lambda_python_name" {
  value = aws_lambda_function.runtime["python"].function_name
}

# Undecidable: "python" has several live vendors and the version is minor-only.
output "expected_lambda_python_cpes" {
  value = []
}

output "lambda_node_name" {
  value = aws_lambda_function.runtime["node"].function_name
}

# "20.x" is not a resolvable version.
output "expected_lambda_node_cpes" {
  value = []
}

# --- Negative controls ------------------------------------------------------

# Substrings that must appear in NO emitted CPE anywhere in the scan. These
# guard the specific mis-vendorings this design names as its anti-goal, and are
# checked across every result rather than per-resource.
#
#   :a:alpine        alpine:3.19 and nginx:1.25.3-alpine must not resolve to
#                    alpine_project:alpine, the email client.
#   :a:nginx:        the vendor position. The correct CPE has nginx as the
#                    PRODUCT (:a:f5:nginx:), so the trailing colon pins this to
#                    the deprecated vendor spelling only.
#   :a:python        python3.12 must emit nothing at all.
#   :a:node          nodejs20.x must emit nothing at all.
#
# The remainder are homonym vendors: unrelated software that shares a product
# string with something the decoders look up. Emitting both vendors of a
# collision is a deliberate decision (see the spec's vendor-aliasing entry), and
# it is only safe because every homonym collision is capped at a version from
# 2004-2018 that will not appear in a container tag or a Lambda runtime — while
# the collisions that do reach current versions (redis 6.2.6, MySQL 5.6.36) are
# true alias pairs naming the same software.
#
# These substrings are what detects that premise breaking. A resolution rule
# loosened to reach homonyms would fabricate inventory, claiming the customer
# runs a Jenkins plugin, a Rails gem or a Node driver.
#
#   :a:mysqljs    the Node mysql driver, not Oracle MySQL
#   :a:jenkins    Jenkins plugins sharing kubernetes/mongodb product names
#   :a:makandra   a Rails gem, not HashiCorp Consul
#   :a:tibco      TIBCO Vault, not HashiCorp Vault
#   :a:tdengine   a Grafana plugin, not Grafana
#   :a:eficode    not InfluxData's InfluxDB
#   :a:voxpupuli  a Puppet module, not RabbitMQ
#   :a:anynines   a service broker, not the upstream datastores
output "forbidden_cpe_substrings" {
  value = [
    ":a:alpine", ":a:nginx:", ":a:python", ":a:node",
    ":a:mysqljs", ":a:jenkins", ":a:makandra", ":a:tibco",
    ":a:tdengine", ":a:eficode", ":a:voxpupuli", ":a:anynines",
  ]
}
