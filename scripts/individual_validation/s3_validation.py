#!/usr/bin/env python3

import sys
import requests

def usage():
    print("Usage: python3 check_s3_exposure.py <bucket_name> <region>")
    print("Example: python3 check_s3_exposure.py my-bucket us-east-1")
    sys.exit(1)

def check_s3_bucket_exposure(bucket_name, region):
    url = f"https://{bucket_name}.s3.{region}.amazonaws.com"
    try:
        response = requests.get(url)
        print(f"Checking exposure for: {url}")
        if response.status_code == 200:
            print("[+] Bucket is PUBLICLY accessible.")
        elif response.status_code == 403:
            print("[-] Bucket exists but access is FORBIDDEN (likely private).")
        elif response.status_code == 404:
            print("[-] Bucket does NOT exist or invalid region.")
        else:
            print(f"[!] Unexpected response: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to bucket: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
    bucket_name = sys.argv[1]
    region = sys.argv[2]
    check_s3_bucket_exposure(bucket_name, region)
