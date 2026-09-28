package compliance.ac3_aws

import rego.v1

# Non_compliant: bucket plus a public access block with all four flags true.
partial_broken_input := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
		{
			"type": "aws_s3_bucket_public_access_block",
			"name": "primary",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_public_access_block.primary",
		"type": "aws_s3_bucket_public_access_block",
		"values": {
			"block_public_acls": true,
			"block_public_policy": false,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		},
	}]}},
}

test_missing_pab_denied_mio if {
	count(deny) == 1 with input as partial_broken_input
}
