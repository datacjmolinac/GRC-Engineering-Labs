\## compliant-s3



This module provisions a compliant AWS S3 bucket pair (primary + log) that enforces five NIST 800-53 controls by design:



\- SC-28: Server-side encryption (AES-256) applied by default to all objects at rest

\- AC-3: All four public access block flags set to true, eliminating every public access vector

\- CM-6: Versioning enabled to preserve object history and prevent unauthorized deletion of evidence

\- AU-3 / AU-6: Server access logging enabled, with logs delivered to a dedicated log bucket with its own encryption and public access controls



No screenshots. Compliance is expressed as code and verified via machine-readable JSON evidence captured with terraform show -json.

