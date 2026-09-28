# METADATA
# title: SC-28 - Encryption at Rest (AWS S3)
# description: Every aws_s3_bucket must have a matching server-side encryption configuration.
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: Add aws_s3_bucket_server_side_encryption_configuration referencing the bucket.
package compliance.sc28_aws

import rego.v1

# YOUR BUILD: deny any aws_s3_bucket that has no matching
# aws_s3_bucket_server_side_encryption_configuration.
#
# Technique: at plan time the bucket name is unknown, so match by reference, not
# value. Bucket addresses live in input.configuration.root_module.resources[]
# (type == "aws_s3_bucket"). The encryption resource references its bucket in
# .expressions.bucket.references (strings like "aws_s3_bucket.primary.id").
#
# Make the two tests in sc28_encryption_aws_test.rego pass. The stub below keeps
# `deny` defined so the tests load. Replace it.


encryption_exists(bucket_ref) if {
	some enc in input.configuration.root_module.resources
	enc.type == "aws_s3_bucket_server_side_encryption_configuration"
	bucket_ref in enc.expressions.bucket.references
}

deny contains msg if {
	some bucket in input.configuration.root_module.resources
	bucket.type == "aws_s3_bucket"
	bucket_ref := sprintf("%s.%s.id", [bucket.type, bucket.name])

	not encryption_exists(bucket_ref)

	msg := sprintf("Bucket %s has no encryption configuration", [bucket.name])
}
