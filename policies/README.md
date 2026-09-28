# Policy-as-Code: NIST 800-53 Controls for S3 (Terraform + OPA/Rego)

This directory contains three Rego policies that read a Terraform plan
(`terraform show -json`) and deny it if it violates a specific NIST 800-53
control. Each policy is unit-tested against fixtures and has also been run
against a real `terraform plan` output from a live AWS S3 module.

## Controls implemented

| Control | Rule | What it checks |
|---|---|---|
| **SC-28** | `sc28_encryption_aws.rego` | Every `aws_s3_bucket` has a matching `aws_s3_bucket_server_side_encryption_configuration` referencing it. |
| **AC-3** | `ac3_no_public_aws.rego` | Every `aws_s3_bucket` has an `aws_s3_bucket_public_access_block` with all four flags (`block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`) set to `true`. Covers both "block missing entirely" and "block present but a flag is false." |
| **CM-6** | `cm6_required_tags_aws.rego` | Every `aws_s3_bucket` carries all four required tags (`Project`, `Environment`, `ManagedBy`, `ComplianceScope`) in `tags_all`. |

## The technique: match by reference, not by value

At plan time, a bucket's final name is unknown — the random suffix hasn't
been generated yet (`(known after apply)`). So a policy can't match a
related resource (an encryption config, a public access block) to its
bucket by comparing names.

Instead, `configuration.root_module.resources` records *expressions* —
each dependent resource's `bucket` argument stores a reference string like
`"aws_s3_bucket.primary.id"`. The policy builds that same reference string
from the bucket's own `type` and `name` (`sprintf("%s.%s.id", [...])`) and
checks whether it appears in the dependent resource's
`expressions.bucket.references` list. Only once a match is confirmed does
the policy cross into `planned_values` (using the resource's `address`) to
read the concrete values Terraform actually intends to set — flags for
AC-3, none needed for SC-28 (existence is enough), and tags directly for
CM-6, which never needs a cross-reference at all because tags live on the
bucket resource itself.

Two smaller gotchas the tests forced out:
- Rego's `not` can't negate a `some ... in ...` search directly — it needs
  to be wrapped in its own rule (`encryption_exists(bucket_ref)`,
  `bucket_has_pab(bucket_ref)`) so there's a clean boolean to negate.
- Accessing a map key that doesn't exist (e.g. a missing tag) fails the
  whole expression rather than returning false — so tag/flag checks also
  go through a small helper rule instead of a raw `not obj.values[key]`.

## Test results — fixtures (`opa test`)

```
$ opa test policies/ -v
...
PASS: 7/7
```

All three controls pass both their compliant and non-compliant fixture
cases (6 tests from the starter spec). A seventh test
(`test_one_flag_missing_denied`, in `ac3_no_public_aws_extra_test.rego`)
was added to close a coverage gap the starter fixtures didn't exercise:
a public access block that exists but has exactly one flag set to
`false`, rather than all four or none. The original AC-3 rule handled
"all missing" and "block absent" correctly but needed the same
one-flag-false case explicitly proven before it was trusted.

## Test results — real infrastructure (`conftest`)

Run against the actual `plan.json` of the Week 1 compliant-s3 module:

```
$ conftest test --policy policies --namespace compliance.sc28_aws plan.json
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test --policy policies --namespace compliance.ac3_aws plan.json
2 tests, 2 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test --policy policies --namespace compliance.cm6_aws plan.json
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
```

To confirm the gate actually catches violations (not just passes by
default), the encryption block for the `log` bucket was commented out in
a copied workspace and the plan regenerated:

```
$ conftest test --policy policies --namespace compliance.sc28_aws plan.json
FAIL - plan.json - compliance.sc28_aws - Bucket log has no encryption configuration

1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

The failure names the specific bucket, confirming the gate is a real
check, not a rule that always passes.
