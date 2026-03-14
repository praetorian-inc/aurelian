output "prefix" {
  value = local.prefix
}

output "zone_id" {
  value = aws_route53_zone.test.zone_id
}

output "zone_name" {
  value = trimsuffix(aws_route53_zone.test.name, ".")
}

# EB CNAME outputs
output "eb_cname_record_name" {
  value = trimsuffix(aws_route53_record.eb_cname.fqdn, ".")
}

output "eb_cname_prefix" {
  value = local.eb_prefix
}

output "eb_cname_target" {
  value = "${local.eb_prefix}.us-east-2.elasticbeanstalk.com"
}

# EIP dangling outputs
output "eip_a_record_name" {
  value = trimsuffix(aws_route53_record.eip_dangling.fqdn, ".")
}

output "dangling_ip" {
  value = local.dangling_ip
}

# NS delegation outputs
output "ns_record_name" {
  value = trimsuffix(aws_route53_record.ns_delegation.fqdn, ".")
}

output "ns_nameservers" {
  value = local.fake_ns
}

# Safe record outputs (for negative testing)
output "safe_cname_record_name" {
  value = trimsuffix(aws_route53_record.safe_cname.fqdn, ".")
}

output "safe_a_record_name" {
  value = trimsuffix(aws_route53_record.safe_a.fqdn, ".")
}
