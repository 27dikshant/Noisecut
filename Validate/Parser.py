import json
import sys
import socket
import subprocess
import boto3
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from typing import Tuple, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def s3_check(bucket: str) -> Tuple[str, Dict[str, Any]]:
    try:
        url = f"http://{bucket}.s3.amazonaws.com/"
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url],
                           capture_output=True, text=True, timeout=5)
        code = r.stdout.strip()
        classification = "TP" if code in ["200", "204"] else "FP"
        return classification, {"http_code": code}
    except Exception as e:
        logging.error(f"S3 check failed for {bucket}: {e}")
        return "Inconclusive", {}

def ec2_check(ip: str) -> Tuple[str, Dict[str, Any]]:
    ports = [22, 3389]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            logging.error(f"EC2 port check error for {ip}:{port} - {e}")
    classification = "TP" if open_ports else "FP"
    return classification, {"open_ports": open_ports}

def iam_check(user: str, aws_region=None) -> Tuple[str, Dict[str, Any]]:
    try:
        session = boto3.Session(region_name=aws_region) if aws_region else boto3.Session()
        iam = session.client("iam")
        keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
        for key in keys:
            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            if "LastUsedDate" in last_used["AccessKeyLastUsed"]:
                return "TP", {
                    "access_key": key["AccessKeyId"],
                    "last_used": str(last_used["AccessKeyLastUsed"]["LastUsedDate"])
                }
        return "FP", {}
    except Exception as e:
        logging.error(f"IAM check failed for {user}: {e}")
        return "Inconclusive", {}

def secret_check(repo_url: str) -> Tuple[str, Dict[str, Any]]:
    try:
        r = subprocess.run(["trufflehog", "git", repo_url, "--json"], capture_output=True, text=True, timeout=15)
        matches = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        classification = "TP" if matches else "FP"
        return classification, {"matches": matches}
    except Exception as e:
        logging.error(f"Secret scan failed for {repo_url}: {e}")
        return "Inconclusive", {}

# Add more resource validation functions here
def rds_check(...):
    pass

def lambda_check(...):
    pass

def load_alerts(input_file: str):
    try:
        with open(input_file) as f:
            data = json.load(f)
        logging.info(f"Loaded {len(data)} alerts from {input_file}")
        return data
    except Exception as e:
        logging.error(f"Failed to load alerts file {input_file}: {e}")
        sys.exit(1)

def get_resource_id(alert: dict):
    # Try different keys based on alert structure
    for key in ["ResourceId", "resource", "Resource", "ResourceName"]:
        if key in alert:
            return alert[key]
    return None

def validate_alert(alert: dict, test_cases: dict, aws_region=None):
    rule_id = alert.get("ControlId") or alert.get("rule_id") or ""
    for key, func in test_cases.items():
        # Use regex for more precise matching if needed
        if re.search(key, rule_id, re.I):
            resource = get_resource_id(alert)
            if not resource:
                logging.warning(f"No resource found for alert with rule_id {rule_id}")
                return None
            classification, evidence = func(resource) if key != "iam-access-key-access-check" else func(resource, aws_region)
            alert["classification"] = classification
            alert["validation_evidence"] = evidence
            return alert
    return None

def main():
    parser = argparse.ArgumentParser(description="Behavioral Validation of Prowler Alerts")
    parser.add_argument("input", help="Prowler JSON input file")
    parser.add_argument("output", help="Output JSON file with validation results")
    parser.add_argument("--aws-region", help="AWS region for IAM checks", default=None)
    parser.add_argument("--threads", type=int, help="Number of concurrent threads", default=5)

    args = parser.parse_args()

    data = load_alerts(args.input)

    test_cases = {
        r"s3-bucket-public-read-prohibited": s3_check,
        r"ec2-instance-no-public-ip": ec2_check,
        r"iam-access-key-access-check": iam_check,
        r"high-entropy-credential-scan": secret_check
    }

    results = []
    seen = set()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_alert = {}
        for alert in data:
            rule_id = alert.get("ControlId") or alert.get("rule_id") or ""
            resource = get_resource_id(alert)
            if not resource or (rule_id, resource) in seen:
                continue
            seen.add((rule_id, resource))
            future = executor.submit(validate_alert, alert, test_cases, args.aws_region)
            future_to_alert[future] = alert

        for future in as_completed(future_to_alert):
            res = future.result()
            if res:
                results.append(res)

    logging.info(f"Validation complete. Writing {len(results)} validated alerts to {args.output}")
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
