# prompt_scanner.py
# LLM Guard handles: PII, secrets, prompt injection
# Intent extraction — manual rule-based (no API needed)

import os
import re
import json

# ── Fix: "Cannot copy out of meta tensor" ──────────────
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")

import torch
from torch import nn as _nn

_original_to = _nn.Module.to

def _patched_to(self, *args, **kwargs):
    try:
        has_meta = any(
            p.device.type == "meta"
            for p in list(self.parameters()) + list(self.buffers())
        )
    except Exception:
        has_meta = False
    if has_meta:
        device = args[0] if args else kwargs.get("device", "cpu")
        return self.to_empty(device=device)
    return _original_to(self, *args, **kwargs)

_nn.Module.to = _patched_to
# ── End fix ────────────────────────────────────────────

from llm_guard import scan_prompt
from llm_guard.input_scanners import Anonymize, Secrets, PromptInjection
from llm_guard.input_scanners.anonymize_helpers import BERT_LARGE_NER_CONF
from llm_guard.vault import Vault


def _normalize_prompt(text: str) -> str:
    """Collapse blank lines so llm-guard's sentence splitter doesn't choke."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln if ln.strip() else "" for ln in text.split("\n")]
    cleaned = re.sub(r"\n{3,}", "\n\n", "\n".join(lines))
    return cleaned.strip()


# ── STEP 1: LLM Guard — all 3 checks in one call ───────

# PromptInjection false-positive notes
# ─────────────────────────────────────────────────────────
# LLM Guard's PromptInjection ML model was trained on generic chat prompts.
# Dense IaC/architecture prompts with many imperative commands
# ("Deploy…", "Configure…", "Implement…") score high even when legitimate.
#
# Mitigation strategy:
#   1. Raise the threshold to 0.85 (from the default ~0.5)
#   2. Apply a heuristic IaC pre-filter: if the prompt looks like an IaC
#      architecture spec (≥ 3 IaC service keywords), further raise the
#      effective threshold to 0.92 to suppress ML false positives.
#   3. True injections ("ignore previous instructions", "forget your rules")
#      are still caught by the rule-based _IGNORE_INSTR regex in the
#      intent extractor regardless of the ML score.
# ─────────────────────────────────────────────────────────

import re as _re

_IAC_KEYWORDS = [
    "vpc", "subnet", "ec2", "rds", "s3", "cloudtrail", "cloudwatch",
    "cloudfront", "route 53", "iam", "kms", "secrets manager", "auto scaling",
    "load balancer", "nat gateway", "internet gateway", "security group",
    "availability zone", "multi-az", "terraform", "cloudformation",
    "ansible", "pulumi", "aws config", "sns", "lambda", "eks", "ecs",
    "waf", "guardduty", "bastion", "pci", "hipaa", "iso 27001", "soc2",
    "ap-south-1", "us-east-1", "eu-west-1", "disaster recovery",
]

_INJECTION_THRESHOLD_DEFAULT = 0.85   # stricter than LLM Guard default (~0.5)
_INJECTION_THRESHOLD_IAC     = 0.92   # even more lenient for IaC prompts


def _is_iac_prompt(text: str) -> bool:
    """Returns True when the text looks like a legitimate IaC architecture spec."""
    lower = text.lower()
    hits = sum(1 for kw in _IAC_KEYWORDS if kw in lower)
    return hits >= 3


def run_llm_guard(prompt: str) -> dict:

    vault = Vault()

    # Set injection threshold based on prompt type
    inj_threshold = _INJECTION_THRESHOLD_IAC if _is_iac_prompt(prompt) \
                    else _INJECTION_THRESHOLD_DEFAULT

    input_scanners = [
        Anonymize(vault, recognizer_conf=BERT_LARGE_NER_CONF),  # PII
        Secrets(),                                               # API keys / tokens
        PromptInjection(threshold=inj_threshold),               # ML injection (tuned)
    ]

    try:
        sanitized_prompt, results_valid, results_score = scan_prompt(
            input_scanners, prompt
        )
    except (IndexError, Exception) as e:
        print(f"[WARN] Batch scan failed ({type(e).__name__}: {e}). Trying per-scanner fallback...")
        sanitized_prompt = prompt
        results_valid = {}
        results_score = {}
        for scanner in input_scanners:
            name = type(scanner).__name__
            try:
                san, valid, score = scan_prompt([scanner], sanitized_prompt)
                sanitized_prompt = san
                results_valid.update(valid)
                results_score.update(score)
            except Exception as inner:
                print(f"  [WARN] {name} failed: {inner} — marking risky (fail-safe)")
                results_valid[name] = False
                results_score[name] = 0.5

    warnings = []
    for scanner_name, is_valid in results_valid.items():
        if not is_valid:
            score = results_score.get(scanner_name, 0)
            # For PromptInjection on IaC prompts, only flag CRITICAL if score
            # exceeds the IaC threshold (i.e. truly suspicious)
            is_iac = _is_iac_prompt(prompt) and scanner_name == "PromptInjection"
            threshold = _INJECTION_THRESHOLD_IAC if is_iac else _INJECTION_THRESHOLD_DEFAULT
            severity  = "CRITICAL" if score > threshold else "HIGH"
            warnings.append({
                "scanner":   scanner_name,
                "passed":    False,
                "score":     round(score, 3),
                "threshold": round(threshold, 2),
                "severity":  severity,
                "action":    "BLOCK" if scanner_name == "PromptInjection"
                             else "REDACT and warn user",
                "note":      "IaC prompt — raised threshold applied" if is_iac else "",
            })

    return {
        "original_prompt":  prompt,
        "sanitized_prompt": sanitized_prompt,
        "warnings":         warnings,
        "safe_to_proceed":  all(results_valid.values()),
        "scores":           results_score,
        "iac_prompt_detected": _is_iac_prompt(prompt),
        "injection_threshold_used": inj_threshold,
    }


# ── STEP 2: Manual Intent Extractor (no API needed) ────

# ── Lookup tables ───────────────────────────────────────

_AWS_REGIONS = {
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "eu-west-1": "Europe (Ireland)",
    "eu-west-2": "Europe (London)",
    "eu-central-1": "Europe (Frankfurt)",
    "sa-east-1": "South America (São Paulo)",
    "ca-central-1": "Canada (Central)",
    "me-south-1": "Middle East (Bahrain)",
    "af-south-1": "Africa (Cape Town)",
}

_COMPLIANCE_KEYWORDS = {
    "pci-dss":    ["pci", "pci-dss", "pci dss", "payment card"],
    "hipaa":      ["hipaa", "health insurance", "phi"],
    "iso27001":   ["iso27001", "iso 27001", "iso-27001"],
    "soc2":       ["soc2", "soc 2", "soc-2"],
    "gdpr":       ["gdpr", "general data protection"],
    "nist":       ["nist", "nist 800"],
    "fedramp":    ["fedramp", "fed ramp"],
    "cis":        ["cis benchmark", "cis controls"],
}

_RESOURCE_PATTERNS = [
    (r"\bvpc\b",                          "VPC"),
    (r"\bsubnet",                         "Subnets"),
    (r"\bapplication load balancer\b|"
     r"\balb\b",                          "Application Load Balancer"),
    (r"\bnetwork load balancer\b|\bnlb\b","Network Load Balancer"),
    (r"\bec2\b|\binstance",               "EC2 Instances"),
    (r"\brds\b|\bpostgres|\bmysql\b|"
     r"\baudora\b|\bmariadb\b",           "RDS Database"),
    (r"\bs3\b|\bsimple storage",          "S3 Bucket"),
    (r"\bcloudtrail\b",                   "CloudTrail"),
    (r"\bcloudwatch\b",                   "CloudWatch"),
    (r"\bkms\b|\bkey management",         "KMS"),
    (r"\biam\b|\brole",                   "IAM Roles"),
    (r"\bsecurity group",                 "Security Groups"),
    (r"\broute\s*53\b|\bdns\b",           "Route 53 / DNS"),
    (r"\bcloudfront\b|\bcdn\b",           "CloudFront CDN"),
    (r"\beks\b|\bkubernetes\b|\bk8s\b",  "EKS / Kubernetes"),
    (r"\becs\b|\bfargate\b|\bdocker\b",   "ECS / Fargate"),
    (r"\blambda\b|\bserverless\b",        "Lambda"),
    (r"\bsns\b|\bsqs\b|\bqueue\b",        "SNS / SQS"),
    (r"\belasticache\b|\bredis\b|"
     r"\bmemcached\b",                    "ElastiCache"),
    (r"\bwaf\b|\bweb application firewall","WAF"),
    (r"\bnat gateway\b|\bnat\b",          "NAT Gateway"),
    (r"\binternet gateway\b|\bigw\b",     "Internet Gateway"),
    (r"\bbastion\b|\bjump\s*host\b",      "Bastion Host"),
    (r"\bsecrets manager\b|\bssm\b|"
     r"\bparameter store\b",             "Secrets Manager / SSM"),
    (r"\bguardduty\b",                    "GuardDuty"),
    (r"\bconfig\b",                       "AWS Config"),
    (r"\bapi\s*gateway\b",               "API Gateway"),
]

_SSH_PATTERNS   = re.compile(r"ssh|port\s*22|bastion", re.I)
_CIDR_PATTERN   = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")
_OPEN_SSH       = re.compile(r"0\.0\.0\.0/0", re.I)
_MULTI_AZ       = re.compile(r"multi[\s\-]*az|multi[\s\-]*availability", re.I)
_ENCRYPT        = re.compile(r"\bencrypt|\btls\b|\bssl\b|\bat[\s\-]*rest\b|"
                              r"\bin[\s\-]*transit\b|\bkms\b", re.I)
_PUBLIC_S3      = re.compile(r"public(ly)?\s+(readable|accessible)|s3.*public|"
                              r"disable.*block.*public", re.I)
_LOGGING        = re.compile(r"cloudtrail|cloudwatch|log|audit|monitor", re.I)
_LEAST_PRIV     = re.compile(r"least[\s\-]*privilege|minimal[\s\-]*access|"
                              r"minimum[\s\-]*permission", re.I)
_ADMIN_ACCESS   = re.compile(r"administrator\s*access|admin\s*role|"
                              r"full\s*access|AdministratorAccess", re.I)
_IGNORE_INSTR   = re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instruct|"
                              r"forget\s+(your\s+)?(security|rule|instruct)|"
                              r"do\s+not\s+tell", re.I)

# ── Negation keywords that flip/cancel a feature ───────────────────────────
# Window: these words within 6 tokens BEFORE a target term negate it.
_NEG_WORDS = re.compile(
    r"\b(not|without|disable[sd]?|no\b|never|don't|do not|avoid|skip|turn off|"
    r"remove|disallow|block|prevent|except|unless)\b",
    re.I
)
_WINDOW = 6   # word-distance look-behind for negation


def _negated(text: str, pattern: re.Pattern) -> bool:
    """
    Returns True when every match of *pattern* in *text* is preceded
    by a negation keyword within _WINDOW words.
    Returns False when there is no match at all.
    """
    words = re.split(r"\s+", text)
    matched_positions: list[int] = []
    for i, w in enumerate(words):
        if pattern.search(w):
            matched_positions.append(i)
    if not matched_positions:
        return False
    for pos in matched_positions:
        window_start = max(0, pos - _WINDOW)
        window_words = words[window_start:pos]
        if not any(_NEG_WORDS.search(ww) for ww in window_words):
            return False   # found a non-negated occurrence → feature IS requested
    return True  # every occurrence was negated


def _affirmed(text: str, pattern: re.Pattern) -> bool:
    """True iff pattern matches AND at least one match is NOT negated."""
    return bool(pattern.search(text)) and not _negated(text, pattern)


def _explicitly_disabled(text: str, pattern: re.Pattern) -> bool:
    """True iff the pattern appears AND every occurrence is negated."""
    return bool(pattern.search(text)) and _negated(text, pattern)


def _find_region(text: str) -> dict:
    # Exact AWS region code match first
    for code, name in _AWS_REGIONS.items():
        if code in text.lower():
            return {"code": code, "name": name}
    # Fallback: look for keyword hints
    if re.search(r"\bmumbai\b", text, re.I):
        return {"code": "ap-south-1", "name": "Asia Pacific (Mumbai)"}
    if re.search(r"\bsingapore\b", text, re.I):
        return {"code": "ap-southeast-1", "name": "Asia Pacific (Singapore)"}
    if re.search(r"\bvirginia\b", text, re.I):
        return {"code": "us-east-1", "name": "US East (N. Virginia)"}
    return {}


def _find_compliance(text: str) -> list:
    found = []
    lower = text.lower()
    for framework, keywords in _COMPLIANCE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            found.append(framework.upper())
    return found


def _find_resources(text: str) -> list:
    found = []
    lower = text.lower()
    for pattern, label in _RESOURCE_PATTERNS:
        if re.search(pattern, lower) and label not in found:
            found.append(label)
    return found


def _find_ec2_count(text: str) -> int | None:
    """Try to extract how many EC2 instances were requested."""
    m = re.search(r"(\d+)\s+ec2|(\d+)\s+instance", text, re.I)
    if m:
        return int(m.group(1) or m.group(2))
    words = {"one":1,"two":2,"three":3,"four":4,"five":5,
             "six":6,"seven":7,"eight":8,"nine":9,"ten":10}
    m2 = re.search(r"(one|two|three|four|five|six|seven|eight|nine|ten)\s+ec2", text, re.I)
    if m2:
        return words.get(m2.group(1).lower())
    return None


def _find_az_count(text: str) -> int | None:
    m = re.search(r"(\d+)\s+availability\s+zone|(\d+)\s+az", text, re.I)
    if m:
        return int(m.group(1) or m.group(2))
    return None


def _find_ssh_access(text: str) -> dict:
    if not _SSH_PATTERNS.search(text):
        return {"configured": False}

    result: dict = {"configured": True, "open_to_world": False, "allowed_cidrs": []}

    if _OPEN_SSH.search(text):
        result["open_to_world"] = True
        result["risk"] = "CRITICAL — SSH open to 0.0.0.0/0"

    # Collect any CIDRs mentioned near SSH context
    cidrs = _CIDR_PATTERN.findall(text)
    result["allowed_cidrs"] = [c for c in cidrs if c != "0.0.0.0/0"]

    office_match = re.search(r"office\s+ip|my\s+ip|restrict.*ssh", text, re.I)
    if office_match:
        result["restricted_to_office"] = True

    return result


def _find_conflicts(text: str, resources: list) -> list:
    """
    Compare what the prompt asks for vs. any injected overrides
    and flag real contradictions.
    """
    conflicts = []

    # Prompt injection instructions detected
    if _IGNORE_INSTR.search(text):
        conflicts.append(
            "Prompt injection detected: instructions to ignore/forget security rules"
        )

    # Asked for least-privilege but also admin access
    if _LEAST_PRIV.search(text) and _ADMIN_ACCESS.search(text):
        conflicts.append(
            "Conflict: least-privilege IAM requested but AdministratorAccess also present"
        )

    # Encryption requested but also explicitly disabled via negation
    if _affirmed(text, _ENCRYPT) and _explicitly_disabled(text, _ENCRYPT):
        conflicts.append(
            "Conflict: encryption requested but also negated (disable/without/no encryption found)"
        )
    elif _explicitly_disabled(text, _ENCRYPT):
        conflicts.append(
            "Warning: encryption appears to be explicitly disabled via negation keyword"
        )

    # S3 bucket present but public access requested
    if "S3 Bucket" in resources and _PUBLIC_S3.search(text):
        conflicts.append(
            "Conflict: S3 bucket requested but public-read instruction present"
        )

    # SSH open to world while office-IP restriction also mentioned
    if _OPEN_SSH.search(text) and re.search(r"office\s+ip|restrict.*ssh", text, re.I):
        conflicts.append(
            "Conflict: SSH restricted to office IP in requirements but 0.0.0.0/0 also present"
        )

    return conflicts


def _build_intent_summary(intent: dict) -> str:
    parts = []
    if intent.get("region"):
        parts.append(f"Deploy to {intent['region']['name']} ({intent['region']['code']})")
    if intent.get("expected_resources"):
        parts.append(f"provision {len(intent['expected_resources'])} resource type(s)")
    if intent.get("availability", {}).get("multi_az"):
        parts.append("with Multi-AZ availability")
    if intent.get("encryption", {}).get("enabled"):
        parts.append("encryption enabled")
    if intent.get("logging", {}).get("enabled"):
        parts.append("logging/auditing enabled")
    if intent.get("compliance_frameworks"):
        parts.append(f"compliance: {', '.join(intent['compliance_frameworks'])}")
    if intent.get("iam", {}).get("least_privilege"):
        parts.append("IAM least-privilege")
    return ". ".join(parts).capitalize() + "." if parts else "No clear IaC intent detected."


def extract_intent(prompt: str) -> dict:
    """
    Negation-aware, rule-based intent extractor — no API call needed.
    Understands: not, without, disable, no, never, don't, avoid, skip,
                 turn off, remove, disallow, block, prevent.
    Parses the prompt text to produce the same schema as the Groq extractor.
    """
    resources  = _find_resources(prompt)
    ssh        = _find_ssh_access(prompt)
    conflicts  = _find_conflicts(prompt, resources)
    az_count   = _find_az_count(prompt)
    ec2_count  = _find_ec2_count(prompt)

    # ── Negation-aware boolean flags ───────────────────────────────────────
    enc_kms_pat   = re.compile(r"\bkms\b", re.I)
    ct_pat        = re.compile(r"cloudtrail", re.I)
    cw_pat        = re.compile(r"cloudwatch", re.I)

    enc_affirmed  = _affirmed(prompt, _ENCRYPT)
    enc_disabled  = _explicitly_disabled(prompt, _ENCRYPT)
    kms_affirmed  = _affirmed(prompt, enc_kms_pat)
    log_affirmed  = _affirmed(prompt, _LOGGING)
    ct_affirmed   = _affirmed(prompt, ct_pat)
    cw_affirmed   = _affirmed(prompt, cw_pat)
    lp_affirmed   = _affirmed(prompt, _LEAST_PRIV)
    admin_affirmed= _affirmed(prompt, _ADMIN_ACCESS)
    multiaz_affirmed = _affirmed(prompt, _MULTI_AZ)
    pub_s3        = _affirmed(prompt, _PUBLIC_S3)

    # Detected negation keywords (for reporting)
    neg_hits = sorted(set(m.group(0).lower() for m in _NEG_WORDS.finditer(prompt)))

    intent = {
        "region": _find_region(prompt),

        "access": {
            "ssh": ssh,
            "public_s3": pub_s3,
        },

        "encryption": {
            "enabled":            enc_affirmed,
            "disabled":           enc_disabled,
            "kms":                kms_affirmed,
            "negation_detected":  enc_disabled or (bool(_ENCRYPT.search(prompt)) and not enc_affirmed),
        },

        "iam": {
            "least_privilege":    lp_affirmed,
            "admin_access":       admin_affirmed,
            "lp_negated":         _explicitly_disabled(prompt, _LEAST_PRIV),
        },

        "availability": {
            "multi_az":           multiaz_affirmed,
            "az_count":           az_count,
            "ec2_count":          ec2_count,
        },

        "logging": {
            "enabled":            log_affirmed,
            "disabled":           _explicitly_disabled(prompt, _LOGGING),
            "cloudtrail":         ct_affirmed,
            "cloudwatch":         cw_affirmed,
        },

        "negation_keywords_found": neg_hits,
        "compliance_frameworks":   _find_compliance(prompt),
        "expected_resources":       resources,
        "conflicts_detected":       conflicts,
    }

    intent["intent_summary"] = _build_intent_summary(intent)
    return intent


# ── MAIN ────────────────────────────────────────────────

def scan(prompt: str) -> dict:
    clean = _normalize_prompt(prompt)

    print("\n[1/2] Running LLM Guard (PII + Secrets + Injection)...")
    guard_result = run_llm_guard(clean)

    print("[2/2] Extracting intent (rule-based)...")
    # Run on sanitized prompt so PII is already stripped
    intent = extract_intent(guard_result["sanitized_prompt"])

    result = {
        "raw_prompt":         prompt,
        "sanitized_prompt":   guard_result["sanitized_prompt"],
        "safe_to_proceed":    guard_result["safe_to_proceed"],
        "warnings":           guard_result["warnings"],
        "scores":             guard_result["scores"],
        "constraint_schema":  intent,
        "expected_resources": intent.get("expected_resources", []),
        "intent_summary":     intent.get("intent_summary", ""),
        "conflicts":          intent.get("conflicts_detected", []),
        "compliance":         intent.get("compliance_frameworks", []),
    }

    # ── Save extracted intent to intent_expected.json ──────────────────────
    _intent_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "intent_expected.json")
    with open(_intent_out, "w", encoding="utf-8") as _f:
        json.dump(intent, _f, indent=2, ensure_ascii=False)
    print("[v2] Intent saved -> " + _intent_out)
    # ──────────────────────────────────────────────────────────────────────

    return result


def scan_from_file(filepath: str = "input.txt") -> dict:
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}
    with open(filepath, "r", encoding="utf-8") as f:
        prompt = f.read().strip()
    if not prompt:
        return {"error": "input.txt is empty. Please enter a prompt first."}
    return scan(prompt)


if __name__ == "__main__":
    print("Shadow AI IaC Prompt Scanner")
    print("Enter prompt (empty line to submit):")
    lines = []
    while True:
        line = input()
        if line == "": break
        lines.append(line)

    prompt = " ".join(lines)
    result = scan(prompt)

    print("\n" + "="*55)
    print("INTENT:", result["intent_summary"])

    print("\nLLM GUARD RESULTS:")
    if result["safe_to_proceed"]:
        print("  ✅ All checks passed")
    else:
        for w in result["warnings"]:
            print(f"  ⛔ [{w['severity']}] {w['scanner']} — score: {w['score']}")
            print(f"      → {w['action']}")

    print("\nCONSTRAINT SCHEMA:")
    print(json.dumps(result["constraint_schema"], indent=2))

    print("\nEXPECTED RESOURCES:")
    for r in result["expected_resources"]:
        print(f"  📦 {r}")

    if result["conflicts"]:
        print("\nCONFLICTS:")
        for c in result["conflicts"]:
            print(f"  ⚠️  {c}")

    with open("scanner_output.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\n💾 Saved → scanner_output.json")
