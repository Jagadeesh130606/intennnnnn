"""
parse_reality.py
================
Parses a generated IaC script and extracts what was ACTUALLY produced,
saving it to reality_received.json for comparison against intent_expected.json.

Usage (standalone):
    python parse_reality.py --iac path/to/script.tf --lang terraform
    python parse_reality.py --iac path/to/script.tf --prompt "original prompt" --model "model-name"

Also importable as a module (used by server.py after generation):
    from parse_reality import extract_and_save
    extract_and_save(iac_code, lang, prompt, model)
"""

import re
import json
import argparse
from datetime import datetime
from pathlib import Path

# Output file path (same folder as this script)
_HERE         = Path(__file__).parent
OUTPUT_FILE   = _HERE / "reality_received.json"


# ── Resource detection patterns (Terraform + CloudFormation + Ansible) ──────
RESOURCE_PATTERNS = {
    "VPC": [
        r'aws_vpc\b', r'"AWS::EC2::VPC"', r'ec2_vpc\b',
        r'name:\s*\w*vpc', r'Type:\s*AWS::EC2::VPC',
    ],
    "Subnets": [
        r'aws_subnet\b', r'"AWS::EC2::Subnet"', r'ec2_subnet\b',
        r'private_subnet', r'public_subnet', r'Type:\s*AWS::EC2::Subnet',
    ],
    "Application Load Balancer": [
        r'aws_lb\b', r'aws_alb\b', r'aws_lb_listener', r'aws_lb_target_group',
        r'"AWS::ElasticLoadBalancingV2::LoadBalancer"',
        r'load_balancer_type\s*=\s*"application"',
    ],
    "Auto Scaling Group": [
        r'aws_autoscaling_group\b', r'aws_launch_template\b',
        r'"AWS::AutoScaling::AutoScalingGroup"',
        r'autoscaling_group', r'AutoScalingGroup',
    ],
    "EC2 Instances": [
        r'aws_instance\b', r'"AWS::EC2::Instance"', r'ec2_instance\b',
        r'amazon_ec2', r'aws_launch_configuration',
    ],
    "RDS Database": [
        r'aws_db_instance\b', r'aws_rds_cluster\b',
        r'"AWS::RDS::DBInstance"', r'"AWS::RDS::DBCluster"',
        r'engine\s*=\s*"postgres"', r'engine\s*=\s*"mysql"',
    ],
    "S3 Bucket": [
        r'aws_s3_bucket\b', r'"AWS::S3::Bucket"',
        r's3_bucket\b', r'aws_s3_',
    ],
    "CloudTrail": [
        r'aws_cloudtrail\b', r'"AWS::CloudTrail::Trail"',
        r'cloudtrail', r'cloud_trail',
    ],
    "CloudWatch": [
        r'aws_cloudwatch\b', r'aws_cloudwatch_log_group\b',
        r'aws_cloudwatch_metric_alarm\b',
        r'"AWS::CloudWatch::', r'"AWS::Logs::',
        r'cloudwatch_logs', r'log_group',
    ],
    "KMS": [
        r'aws_kms_key\b', r'aws_kms_alias\b',
        r'"AWS::KMS::Key"', r'kms_key_id',
        r'kms_master_key_id', r'aws_kms_',
    ],
    "IAM Roles": [
        r'aws_iam_role\b', r'aws_iam_policy\b',
        r'aws_iam_instance_profile\b', r'aws_iam_role_policy\b',
        r'"AWS::IAM::Role"', r'"AWS::IAM::Policy"',
        r'iam_role', r'iam_policy',
    ],
    "Security Groups": [
        r'aws_security_group\b', r'"AWS::EC2::SecurityGroup"',
        r'security_group_id', r'aws_security_group_rule',
    ],
    "NAT Gateway": [
        r'aws_nat_gateway\b', r'"AWS::EC2::NatGateway"',
        r'nat_gateway', r'nat_gw',
    ],
    "Internet Gateway": [
        r'aws_internet_gateway\b', r'"AWS::EC2::InternetGateway"',
        r'internet_gateway', r'igw',
    ],
    "Route Tables": [
        r'aws_route_table\b', r'"AWS::EC2::RouteTable"',
        r'route_table', r'aws_route\b',
    ],
    "Secrets Manager / SSM": [
        r'aws_secretsmanager_secret\b', r'aws_ssm_parameter\b',
        r'"AWS::SecretsManager::Secret"', r'"AWS::SSM::Parameter"',
        r'secrets_manager', r'secretsmanager',
    ],
    "SNS / SQS": [
        r'aws_sns_topic\b', r'aws_sqs_queue\b',
        r'"AWS::SNS::Topic"', r'"AWS::SQS::Queue"',
    ],
    "CloudFront CDN": [
        r'aws_cloudfront_distribution\b',
        r'"AWS::CloudFront::Distribution"',
        r'cloudfront',
    ],
    "Route 53 / DNS": [
        r'aws_route53_', r'"AWS::Route53::',
        r'route53', r'hosted_zone',
    ],
    "AWS Config": [
        r'aws_config_', r'"AWS::Config::',
        r'aws_config_rule', r'config_recorder',
    ],
    "EKS / Kubernetes": [
        r'aws_eks_', r'"AWS::EKS::',
        r'kubernetes', r'helm_release',
    ],
    "Lambda": [
        r'aws_lambda_function\b', r'"AWS::Lambda::Function"',
        r'lambda_function',
    ],
}


# ── Security feature detection ───────────────────────────────────────────────
SECURITY_PATTERNS = {
    "encryption": {
        "enabled": [
            r'storage_encrypted\s*=\s*true',
            r'encrypted\s*=\s*true',
            r'kms_key_id\s*=',
            r'server_side_encryption',
            r'SSEAlgorithm',
            r'enable_key_rotation',
            r'encryption_at_rest',
        ],
        "disabled": [
            r'storage_encrypted\s*=\s*false',
            r'encrypted\s*=\s*false',
        ],
        "kms": [r'aws_kms_key', r'kms_key_id', r'"AWS::KMS::Key"'],
        "negation_detected": [
            r'no\s+encryption', r'skip.encr', r'disable.encr',
        ],
    },
    "iam": {
        "least_privilege": [
            r'least.privilege', r'minimal.perm', r'specific.*action',
            r'"Action":\s*\[', r'allow.*specific',
        ],
        "admin_access": [
            r'"Action":\s*"\*"', r"'Action':\s*'\\*'",
            r'AdministratorAccess', r'PowerUserAccess',
            r'actions\s*=\s*\["\*"\]',
        ],
        "lp_negated": [
            r'full.access', r'all.permissions', r'admin.*role',
        ],
    },
    "logging": {
        "enabled": [
            r'enable_logging\s*=\s*true',
            r'cloudtrail', r'log_group', r'access_logs',
            r'logging_configuration', r'enable_dns_support',
        ],
        "disabled": [r'enable_logging\s*=\s*false'],
        "cloudtrail": [r'aws_cloudtrail\b', r'"AWS::CloudTrail::Trail"'],
        "cloudwatch": [r'aws_cloudwatch', r'"AWS::CloudWatch::"', r'log_group'],
    },
    "access": {
        "ssh_configured": [r'port\s*=\s*22', r'"22"', r'ssh'],
        "open_to_world": [r'0\.0\.0\.0/0', r'"0\.0\.0\.0/0"'],
        "public_s3": [
            r'acl\s*=\s*"public-read"',
            r'"PublicRead"', r'public_access_block.*false',
        ],
    },
    "availability": {
        "multi_az": [
            r'multi_az\s*=\s*true',
            r'availability_zones\s*=\s*\[',
            r'MultiAZ:\s*true',
        ],
    },
    "tagging": {
        "present": [r'tags\s*=\s*\{', r'"Tags":', r'tags:'],
    },
}


# ── Region detection ─────────────────────────────────────────────────────────
REGION_CODES = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "eu-west-1": "Europe (Ireland)",
    "eu-central-1": "Europe (Frankfurt)",
    "eu-west-2": "Europe (London)",
    "ca-central-1": "Canada (Central)",
    "sa-east-1": "South America (São Paulo)",
}

COMPLIANCE_KEYWORDS = {
    "PCI-DSS":   [r'pci.?dss', r'pci\b', r'payment.card'],
    "HIPAA":     [r'hipaa'],
    "SOC2":      [r'soc.?2', r'soc2'],
    "ISO27001":  [r'iso.?27001'],
    "GDPR":      [r'gdpr'],
    "NIST":      [r'nist'],
    "CIS":       [r'cis\b', r'cis.benchmark'],
}


# ── Core extraction logic ─────────────────────────────────────────────────────
def _check(code: str, patterns: list[str]) -> bool:
    return any(re.search(p, code, re.IGNORECASE) for p in patterns)


def detect_region(code: str) -> dict:
    for code_key, name in REGION_CODES.items():
        if re.search(re.escape(code_key), code, re.IGNORECASE):
            return {"code": code_key, "name": name}
    return {"code": None, "name": None}


def detect_resources(code: str) -> dict:
    """Returns {resource_name: True/False} for every known resource type."""
    return {name: _check(code, patterns) for name, patterns in RESOURCE_PATTERNS.items()}


def detect_security(code: str) -> dict:
    """Returns structured security analysis matching intent_expected.json shape."""
    enc = SECURITY_PATTERNS["encryption"]
    iam = SECURITY_PATTERNS["iam"]
    log = SECURITY_PATTERNS["logging"]
    acc = SECURITY_PATTERNS["access"]
    avl = SECURITY_PATTERNS["availability"]
    tag = SECURITY_PATTERNS["tagging"]

    # Count instances for ec2 count estimation
    ec2_matches = re.findall(r'aws_instance\b', code, re.IGNORECASE)

    # SSH open-to-world check (port 22 + 0.0.0.0/0 in same block)
    has_ssh  = _check(code, acc["ssh_configured"])
    open_ssh = _check(code, acc["open_to_world"]) and has_ssh

    return {
        "encryption": {
            "enabled":           _check(code, enc["enabled"]),
            "disabled":          _check(code, enc["disabled"]),
            "kms":               _check(code, enc["kms"]),
            "negation_detected": _check(code, enc["negation_detected"]),
        },
        "iam": {
            "least_privilege": _check(code, iam["least_privilege"]),
            "admin_access":    _check(code, iam["admin_access"]),
            "lp_negated":      _check(code, iam["lp_negated"]),
        },
        "logging": {
            "enabled":    _check(code, log["enabled"]),
            "disabled":   _check(code, log["disabled"]),
            "cloudtrail": _check(code, log["cloudtrail"]),
            "cloudwatch": _check(code, log["cloudwatch"]),
        },
        "access": {
            "ssh": {
                "configured":          has_ssh,
                "open_to_world":       open_ssh,
                "restricted_to_office": has_ssh and not open_ssh,
            },
            "public_s3": _check(code, acc["public_s3"]),
        },
        "availability": {
            "multi_az":  _check(code, avl["multi_az"]),
            "ec2_count": len(ec2_matches) or None,
        },
        "tagging": {
            "present": _check(code, tag["present"]),
        },
    }


def detect_compliance(code: str) -> list[str]:
    found = []
    for framework, patterns in COMPLIANCE_KEYWORDS.items():
        if _check(code, patterns):
            found.append(framework)
    return found


def build_intent_summary(resources: dict, security: dict, region: dict) -> str:
    parts = []
    if region["code"]:
        parts.append(f"Deployed to {region['name']} ({region['code']})")
    found_res = [k for k, v in resources.items() if v]
    parts.append(f"{len(found_res)} resource type(s) detected")
    if security["availability"]["multi_az"]:
        parts.append("multi-AZ availability present")
    if security["encryption"]["enabled"]:
        parts.append("encryption implemented")
    if security["logging"]["enabled"]:
        parts.append("logging/auditing present")
    if security["iam"]["least_privilege"]:
        parts.append("IAM least-privilege found")
    if security["iam"]["admin_access"]:
        parts.append("⚠️ admin/wildcard IAM detected")
    if not security["tagging"]["present"]:
        parts.append("⚠️ no resource tags found")
    return ". ".join(parts) + "."


def extract_reality(
    iac_code:       str,
    lang:           str  = "terraform",
    original_prompt: str = "",
    model_used:     str  = "",
) -> dict:
    """
    Parse the IaC script and return a structured dict that mirrors
    the shape of intent_expected.json.
    """
    resources  = detect_resources(iac_code)
    security   = detect_security(iac_code)
    region     = detect_region(iac_code)
    compliance = detect_compliance(iac_code)
    found_res  = [k for k, v in resources.items() if v]

    reality = {
        # ── Meta ──────────────────────────────────────────────────
        "generated_at":    datetime.now().isoformat(),
        "model_used":      model_used,
        "language":        lang,
        "original_prompt": original_prompt,
        "lines_of_code":   len(iac_code.splitlines()),

        # ── Mirrors intent_expected.json fields ───────────────────
        "region":    region,
        "access":    security["access"],
        "encryption": security["encryption"],
        "iam":       security["iam"],
        "availability": security["availability"],
        "logging":   security["logging"],
        "tagging":   security["tagging"],

        "compliance_frameworks": compliance,

        # All resource types found in the IaC
        "detected_resources": resources,
        "resource_list":      found_res,
        "resource_count":     len(found_res),

        # Potential issues flagged
        "issues_detected": _detect_issues(security),

        # One-line summary
        "reality_summary": build_intent_summary(resources, security, region),

        # Preview of the raw IaC (first 800 chars)
        "iac_preview": iac_code[:800] + ("…" if len(iac_code) > 800 else ""),
    }
    return reality


def _detect_issues(security: dict) -> list[str]:
    issues = []
    if security["iam"]["admin_access"]:
        issues.append("Admin/wildcard IAM actions detected — violates least-privilege")
    if not security["encryption"]["enabled"]:
        issues.append("No encryption-at-rest markers found")
    if not security["logging"]["cloudtrail"]:
        issues.append("CloudTrail not detected in generated script")
    if security["access"]["public_s3"]:
        issues.append("S3 bucket may be publicly accessible")
    if security["access"]["ssh"]["open_to_world"]:
        issues.append("SSH (port 22) open to 0.0.0.0/0")
    if not security["tagging"]["present"]:
        issues.append("No resource tags found — tagging best practice missing")
    return issues


def extract_and_save(
    iac_code:        str,
    lang:            str = "terraform",
    original_prompt: str = "",
    model_used:      str = "",
    output_path:     str = None,
) -> dict:
    """
    Parse the IaC, build the reality dict, write to reality_received.json,
    and return the dict.
    Called by server.py after successful generation.
    """
    reality = extract_reality(iac_code, lang, original_prompt, model_used)
    out = Path(output_path) if output_path else OUTPUT_FILE
    out.write_text(json.dumps(reality, indent=2), encoding="utf-8")
    print(f"[parse_reality] ✅ Saved {out} — {reality['resource_count']} resources, "
          f"{len(reality['issues_detected'])} issues")
    return reality


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse a generated IaC script into reality_received.json")
    parser.add_argument("--iac",    required=True,  help="Path to the IaC script file")
    parser.add_argument("--lang",   default="terraform", help="IaC language: terraform|cloudformation|pulumi|ansible")
    parser.add_argument("--prompt", default="",     help="Original user prompt (optional)")
    parser.add_argument("--model",  default="",     help="AI model used (optional)")
    parser.add_argument("--out",    default=None,   help="Output JSON path (default: reality_received.json)")
    args = parser.parse_args()

    iac_path = Path(args.iac)
    if not iac_path.exists():
        print(f"❌ File not found: {iac_path}")
        raise SystemExit(1)

    iac_code = iac_path.read_text(encoding="utf-8")
    reality  = extract_and_save(iac_code, args.lang, args.prompt, args.model, args.out)

    print(json.dumps(reality, indent=2))
