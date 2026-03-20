output "public_in_use_ami_id" {
  value = aws_ami_copy.public_in_use.id
}

output "public_stale_ami_id" {
  value = aws_ami_copy.public_stale.id
}

output "private_ami_id" {
  value = aws_ami_copy.private.id
}

output "instance_id" {
  value = aws_instance.using_public_ami.id
}

output "prefix" {
  value = local.prefix
}
