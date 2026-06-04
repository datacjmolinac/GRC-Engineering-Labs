import boto3
import json
from datetime import datetime, timezone

BUCKET_NAME = "grc-lab-evidence-carlos-2026"
OUTPUT_FILE = "evidence_report.json"

def check_sc28(s3):
    """SC-28: Protection of Information at Rest"""
    try:
        r = s3.get_bucket_encryption(Bucket=BUCKET_NAME)
        rules = r["ServerSideEncryptionConfiguration"]["Rules"]
        algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        return {
            "control_id": "SC-28",
            "title": "Protection of Information at Rest",
            "status": "PASS" if algo == "aws:kms" else "FAIL",
            "evidence": {
                "sse_algorithm": algo,
                "bucket": BUCKET_NAME
            }
        }
    except Exception as e:
        return {
            "control_id": "SC-28",
            "title": "Protection of Information at Rest",
            "status": "FAIL",
            "evidence": {"error": str(e)}
        }

def check_ac3(s3):
    """AC-3: Access Enforcement"""
    try:
        r = s3.get_public_access_block(Bucket=BUCKET_NAME)
        config = r["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config["BlockPublicAcls"],
            config["IgnorePublicAcls"],
            config["BlockPublicPolicy"],
            config["RestrictPublicBuckets"]
        ])
        return {
            "control_id": "AC-3",
            "title": "Access Enforcement",
            "status": "PASS" if all_blocked else "FAIL",
            "evidence": config
        }
    except Exception as e:
        return {
            "control_id": "AC-3",
            "title": "Access Enforcement",
            "status": "FAIL",
            "evidence": {"error": str(e)}
        }

def check_cm6(s3):
    """CM-6: Configuration Settings"""
    try:
        r = s3.get_bucket_versioning(Bucket=BUCKET_NAME)
        status = r.get("Status", "Disabled")
        return {
            "control_id": "CM-6",
            "title": "Configuration Settings",
            "status": "PASS" if status == "Enabled" else "FAIL",
            "evidence": {
                "versioning_status": status,
                "bucket": BUCKET_NAME
            }
        }
    except Exception as e:
        return {
            "control_id": "CM-6",
            "title": "Configuration Settings",
            "status": "FAIL",
            "evidence": {"error": str(e)}
        }

def check_au3_au6(s3):
    """AU-3 / AU-6: Audit Records"""
    try:
        r = s3.get_bucket_logging(Bucket=BUCKET_NAME)
        logging = r.get("LoggingEnabled", None)
        enabled = logging is not None
        return {
            "control_id": "AU-3/AU-6",
            "title": "Content of Audit Records / Audit Review",
            "status": "PASS" if enabled else "FAIL",
            "evidence": {
                "logging_enabled": enabled,
                "target_bucket": logging.get("TargetBucket") if enabled else None,
                "target_prefix": logging.get("TargetPrefix") if enabled else None
            }
        }
    except Exception as e:
        return {
            "control_id": "AU-3/AU-6",
            "title": "Content of Audit Records / Audit Review",
            "status": "FAIL",
            "evidence": {"error": str(e)}
        }

def main():
    s3 = boto3.client("s3", region_name="us-east-1")

    results = [
        check_sc28(s3),
        check_ac3(s3),
        check_cm6(s3),
        check_au3_au6(s3)
    ]

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "bucket": BUCKET_NAME,
            "framework": "NIST 800-53",
            "lab": "CGE-P Lab 2.3",
            "author": "Carlos J. Molina"
        },
        "summary": {
            "total_controls": len(results),
            "passed": passed,
            "failed": failed,
            "compliance_percentage": round((passed / len(results)) * 100, 1)
        },
        "controls": results
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nEvidence report generated: {OUTPUT_FILE}")
    print(f"Controls: {passed}/{len(results)} PASS ({report['summary']['compliance_percentage']}%)")
    for r in results:
        icon = "✓" if r["status"] == "PASS" else "✗"
        print(f"  {icon} {r['control_id']} — {r['status']}")

if __name__ == "__main__":
    main()