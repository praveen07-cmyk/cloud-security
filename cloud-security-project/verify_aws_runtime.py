"""
verify_aws_runtime.py
------------------------------------------------
Standalone verification script for AWS runtime environment.
Checks STS, CloudTrail, EventBridge, and SQS connectivity.
"""

import os
import sys
import json
import boto3
from dotenv import load_dotenv

load_dotenv()

def verify():
    profile = os.environ.get("AWS_PROFILE", "cloud-security")
    region = os.environ.get("AWS_REGION", "ap-south-1")
    queue_url = os.environ.get("AWS_EVENT_QUEUE_URL", "https://sqs.ap-south-1.amazonaws.com/774075583705/cloudsec-events-queue")
    rule_name = os.environ.get("AWS_EVENT_RULE_NAME", "cloudsec-ai-security-events")
    trail_name = os.environ.get("AWS_TRAIL_NAME", "cloudsec-trail")

    print(f"--- AWS Runtime Verifier ---")
    print(f"Profile: {profile} | Region: {region}")

    results = {
        "STS": "FAIL",
        "CloudTrail": "FAIL",
        "EventBridge": "FAIL",
        "SQS": "FAIL"
    }

    session = boto3.Session(profile_name=profile if profile != "default" else None, region_name=region)

    # 1. STS
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        results["STS"] = "PASS"
        print(f"[PASS] STS: Connected as {identity.get('Arn')}")
    except Exception as e:
        print(f"[FAIL] STS: {e}")

    # 2. CloudTrail
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(trailNameList=[trail_name])
        if trails.get("trailList"):
            status = ct.get_trail_status(Name=trails["trailList"][0]["TrailARN"])
            if status.get("IsLogging"):
                results["CloudTrail"] = "PASS"
                print(f"[PASS] CloudTrail: Trail '{trail_name}' is active and logging.")
            else:
                print(f"[FAIL] CloudTrail: Trail '{trail_name}' exists but is not logging.")
        else:
            print(f"[FAIL] CloudTrail: Trail '{trail_name}' not found.")
    except Exception as e:
        print(f"[FAIL] CloudTrail: {e}")

    # 3. EventBridge
    try:
        ev = session.client("events")
        rule = ev.describe_rule(Name=rule_name)
        targets = ev.list_targets_by_rule(Rule=rule_name)
        if rule.get("State") == "ENABLED" and targets.get("Targets"):
            results["EventBridge"] = "PASS"
            print(f"[PASS] EventBridge: Rule '{rule_name}' is ENABLED with {len(targets['Targets'])} target(s).")
        else:
            print(f"[FAIL] EventBridge: Rule enabled: {rule.get('State')}, Targets count: {len(targets.get('Targets', []))}")
    except Exception as e:
        print(f"[FAIL] EventBridge: {e}")

    # 4. SQS
    try:
        sqs = session.client("sqs")
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        if attrs.get("Attributes", {}).get("QueueArn"):
            results["SQS"] = "PASS"
            print(f"[PASS] SQS: Queue attributes retrieved successfully for '{queue_url}'.")
        else:
            print(f"[FAIL] SQS: Could not retrieve QueueArn.")
    except Exception as e:
        print(f"[FAIL] SQS: {e}")

    print("\n--- Summary ---")
    for key, val in results.items():
        print(f"{key}: {val}")

    all_pass = all(v == "PASS" for v in results.values())
    if not all_pass:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    verify()
