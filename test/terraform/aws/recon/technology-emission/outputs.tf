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

# nginx:1.25.3 -> live vendor f5 (nginx has exactly one dictionary vendor).
# alpine:3.19 -> nothing: the OS-base-image guard still holds.
output "expected_controls_cpes" {
  value = ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"]
}

output "taskdef_parsing_family" {
  value = aws_ecs_task_definition.parsing.family
}

# Four images, three CPEs: registry-qualified postgres, httpd -> http_server,
# nginx with a variant-suffixed tag. nginx:latest -> nothing.
# One CPE per vendor the dictionary lists for each product, all at the observed
# version. Since 2026-11-24 vendor selection no longer narrows by version — see
# pkg/cpe.ResolveVendors for the NVD CVE measurement behind that — so a product
# with nine dictionary vendors emits nine CPEs. The extra vendors match no CVE
# at a version they never shipped; they are inert.
output "expected_parsing_cpes" {
  value = [
    "cpe:2.3:a:anynines:postgresql:15.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:akka:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:dart:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:hp:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:http_server_project:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:ibm:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:novell:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:oracle:http_server:2.4.58:*:*:*:*:*:*:*",
    "cpe:2.3:a:treck:http_server:2.4.58:*:*:*:*:*:*:*",
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
    "cpe:2.3:a:anynines:redis:6.2.6:*:*:*:*:*:*:*",
    "cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*",
    "cpe:2.3:a:redis.js:redis:6.2.6:*:*:*:*:*:*:*",
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

# Emitted since 2026-11-24. Previously [] because no dictionary entry carried
# "3.12"; measured, python 3.12 matches 15 CVEs through NVD's version ranges,
# which do not require one.
output "expected_lambda_python_cpes" {
  value = [
    "cpe:2.3:a:microsoft:python:3.12:*:*:*:*:*:*:*",
    "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*",
  ]
}

output "lambda_node_name" {
  value = aws_lambda_function.runtime["node"].function_name
}

# "20.x" normalises to "20", which is emitted under both node.js vendors.
output "expected_lambda_node_cpes" {
  value = [
    "cpe:2.3:a:joyent:node.js:20:*:*:*:*:*:*:*",
    "cpe:2.3:a:nodejs:node.js:20:*:*:*:*:*:*:*",
  ]
}

# --- Negative controls ------------------------------------------------------

# Substrings that must appear in NO emitted CPE anywhere in the scan.
#
# This list used to be long. It encoded a rule — "the observed version selects
# the vendor" — whose purpose was to keep homonym vendors out: unrelated
# software sharing a product string, like voxpupuli:rabbitmq (a Puppet module)
# or mysqljs:mysql (a Node driver).
#
# That rule was retired on 2026-11-24 after measuring it against the live NVD
# CVE corpus, and most of this list went with it. Homonyms are now emitted and
# are inert: a vendor that never shipped the observed version matches no CVE.
# Excluding them was costing real CVEs — http_server matched 11 of its 15,
# openjdk 2 of 13 — because a product's CVEs are filed under several vendors
# and there is no way to keep the homonyms out that does not also drop those.
#
# What remains are the two controls that are still about a WRONG PRODUCT rather
# than an extra vendor:
#
#   :a:alpine   alpine:3.19 and nginx:1.25.3-alpine must not resolve to
#               alpine_project:alpine, the Pine-successor EMAIL CLIENT. CPE
#               files operating systems under part "o" and the generator keeps
#               only part "a", so this is the one "a"-part alpine there is.
#   :a:nginx:   the VENDOR position. The correct CPE has nginx as the product
#               (:a:f5:nginx:), so the trailing colon pins this to the
#               deprecated vendor spelling only.
#
# The invariant that replaced the rest is asserted directly in
# technology_emission_test.go: every emitted CPE must carry the version that
# was observed, verbatim. That is what actually prevents fabricated inventory
# now — a wrong version attributes wrong CVEs, while an extra vendor at the
# right version attributes none.
output "forbidden_cpe_substrings" {
  value = [":a:alpine", ":a:nginx:"]
}
