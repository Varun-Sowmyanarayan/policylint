import json
import os
import urllib.parse

# Fake AWS keys. moto never talks to real AWS, so these are just placeholders.
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

import boto3
from moto import mock_aws


def policy(effect, actions, resources):
    """Build a simple IAM policy document with one rule (statement)."""
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": actions, "Resource": resources}],
    }


# 8 sensible policies and 4 deliberately dangerous ones
FAKE_POLICIES = {
    "ReadOnlyS3Reports": policy(
        "Allow", ["s3:GetObject", "s3:ListBucket"],
        ["arn:aws:s3:::company-reports", "arn:aws:s3:::company-reports/*"]),
    "S3WriteUploads": policy(
        "Allow", ["s3:PutObject"], ["arn:aws:s3:::company-uploads/*"]),
    "LambdaBasicLogs": policy(
        "Allow", ["logs:CreateLogGroup", "logs:PutLogEvents"],
        ["arn:aws:logs:*:*:*"]),
    "DynamoReadUsers": policy(
        "Allow", ["dynamodb:GetItem", "dynamodb:Query"],
        ["arn:aws:dynamodb:eu-west-1:123456789012:table/Users"]),
    "SQSSendOnly": policy(
        "Allow", ["sqs:SendMessage"],
        ["arn:aws:sqs:eu-west-1:123456789012:alerts-queue"]),
    "SNSPublishAlerts": policy(
        "Allow", ["sns:Publish"],
        ["arn:aws:sns:eu-west-1:123456789012:security-alerts"]),
    "CloudWatchPutMetrics": policy("Allow", ["cloudwatch:PutMetricData"], ["*"]),
    "BlockDeleteBucket": policy("Deny", ["s3:DeleteBucket"], ["*"]),
    # --- the dangerous ones ---
    "AdminEverything": policy("Allow", ["*"], ["*"]),
    "S3FullAccessAll": policy("Allow", ["s3:*"], ["*"]),
    "IAMFullAccessAll": policy("Allow", ["iam:*"], ["*"]),
    "DevHelperTemp": policy(
        "Allow", ["ec2:DescribeInstances", "*"],
        ["arn:aws:ec2:eu-west-1:123456789012:instance/*"]),
}


def as_list(value):
    """AWS lets a value be one item or a list. Always give back a list."""
    return value if isinstance(value, list) else [value]


def load_document(document):
    """AWS may hand the policy back as text. Turn it into a Python dictionary."""
    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    return document


def find_problems(document):
    """Return a list of reasons why this policy is risky (empty list = OK)."""
    problems = []
    for statement in as_list(document["Statement"]):
        if statement.get("Effect") != "Allow":
            continue  # "Deny" rules only take permissions away, so they are safe
        actions = as_list(statement.get("Action", []))
        resources = as_list(statement.get("Resource", []))
        for action in actions:
            if action == "*":
                problems.append("allows EVERY action")
            elif action.endswith(":*") and "*" in resources:
                service = action.split(":")[0]
                problems.append(f"allows ALL {service} actions on EVERY resource")
    return problems


def main():
    with mock_aws():
        iam = boto3.client("iam")

        # 1. Create the fake policies in the pretend AWS
        for name, document in FAKE_POLICIES.items():
            iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(document))
        print(f"Created {len(FAKE_POLICIES)} fake IAM policies")

        # 2. Read them back, like a real auditor would
        results = []
        for item in iam.list_policies(Scope="Local")["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=item["Arn"], VersionId=item["DefaultVersionId"]
            )
            document = load_document(version["PolicyVersion"]["Document"])
            results.append((item["PolicyName"], find_problems(document)))

    # 3. Print the report, risky policies first
    results.sort(key=lambda pair: (len(pair[1]) == 0, pair[0]))

    print("\n=== PolicyLint report ===")
    print(f"{'LABEL':<8}{'POLICY':<24}REASON")
    for name, problems in results:
        label = "RISKY" if problems else "OK"
        reason = "; ".join(problems) if problems else "-"
        print(f"{label:<8}{name:<24}{reason}")

    risky_count = sum(1 for _, problems in results if problems)
    print(f"\n{len(results) - risky_count} policies OK, {risky_count} policies RISKY")


if __name__ == "__main__":
    main()
    