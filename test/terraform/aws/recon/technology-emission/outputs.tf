# The expected CPE strings below are written by hand, not derived from the
# code under test. That is the point: a test that computed them by calling
# software.Detect would compare the system to itself and pass no matter what
# the decoder emitted. These literals are the contract.

output "test_regions" {
  value = [var.region]
}

# --- Tier 2: ECS container images ---

output "taskdef_arn" {
  value = aws_ecs_task_definition.technology.arn
}

output "taskdef_family" {
  value = aws_ecs_task_definition.technology.family
}

# nginx:1.25.3 resolves to the live vendor f5, never the deprecated nginx.
output "expected_taskdef_cpes" {
  value = ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"]
}

# --- Tier 1: Lambda runtimes ---

output "lambda_resolvable_name" {
  value = aws_lambda_function.resolvable_runtime.function_name
}

output "lambda_resolvable_arn" {
  value = aws_lambda_function.resolvable_runtime.arn
}

output "expected_lambda_cpes" {
  value = ["cpe:2.3:a:oracle:openjdk:21:*:*:*:*:*:*:*"]
}

output "lambda_undecidable_name" {
  value = aws_lambda_function.undecidable_runtime.function_name
}

output "lambda_undecidable_arn" {
  value = aws_lambda_function.undecidable_runtime.arn
}

# --- Negative controls ---

# Substrings that must appear in NO emitted CPE anywhere in the scan.
#
#   alpine  — alpine:3.19 must not resolve to alpine_project:alpine, the email
#             client. This is the mis-vendoring the design names as its anti-goal.
#   nginx:  — guards the vendor field specifically: "cpe:2.3:a:nginx:" is the
#             deprecated vendor. The expected CPE has nginx as the PRODUCT, so
#             this substring includes the trailing colon to match vendor position.
#   python  — python3.12 is undecidable and must emit nothing.
output "forbidden_cpe_substrings" {
  value = [":a:alpine", ":a:alpine_project", ":a:nginx:", ":a:python"]
}
