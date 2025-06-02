import boto3
import getpass
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

def validate_aws_credentials(access_key: str, secret_key: str, region: str):
    try:
        # Create a session with provided credentials
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        # Test by listing S3 buckets
        s3 = session.client('s3')
        s3.list_buckets()

        print("✅ AWS credentials are valid.")
        return True

    except NoCredentialsError:
        print("❌ No credentials provided.")
    except PartialCredentialsError:
        print("❌ Incomplete credentials.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ("AuthFailure", "InvalidClientTokenId", "SignatureDoesNotMatch"):
            print(f"❌ Invalid credentials: {error_code}")
        else:
            print(f"❌ AWS ClientError: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    return False

if __name__ == "__main__":
    print("🔐 Enter your AWS credentials to validate:")

    access_key = input("AWS Access Key ID: ").strip()
    secret_key = getpass.getpass("AWS Secret Access Key: ").strip()
    region = input("AWS Region (e.g., us-east-1): ").strip()

    if not region:
        print("❌ Region is required.")
    else:
        validate_aws_credentials(access_key, secret_key, region)
