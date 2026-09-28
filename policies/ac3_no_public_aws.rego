# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: Every aws_s3_bucket must have a public access block with all four flags true.
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: Add aws_s3_bucket_public_access_block referencing the bucket, all four flags true.

package compliance.ac3_aws

import rego.v1

# TODO (your build): deny any aws_s3_bucket that does not have a matching
# aws_s3_bucket_public_access_block with all four flags set to true.

deny contains msg if {
	some bucket in input.configuration.root_module.resources
	bucket.type == "aws_s3_bucket"
	bucket_ref := sprintf("%s.%s.id", [bucket.type, bucket.name])

	some pab in input.configuration.root_module.resources
	pab.type == "aws_s3_bucket_public_access_block"
	bucket_ref in pab.expressions.bucket.references

	pab_address := sprintf("%s.%s", [pab.type, pab.name])
	some pab_values in input.planned_values.root_module.resources
	pab_values.address == pab_address

	required_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	some flag in required_flags
	not pab_values.values[flag]

	msg := sprintf("Bucket %s is missing public access flag: %s", [bucket.name, flag])
}
bucket_has_pab(bucket_ref) if {
	some pab in input.configuration.root_module.resources
	pab.type == "aws_s3_bucket_public_access_block"
	bucket_ref in pab.expressions.bucket.references
}

deny contains msg if {
	some bucket in input.configuration.root_module.resources
	bucket.type == "aws_s3_bucket"
	bucket_ref := sprintf("%s.%s.id", [bucket.type, bucket.name])

	not bucket_has_pab(bucket_ref)

	msg := sprintf("Bucket %s has no public access block at all", [bucket.name])
}
