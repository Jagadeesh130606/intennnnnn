"""
server.py - Flask backend for the Shadow AI IaC Security Dashboard
Bridges the HTML UI with the v2.py prompt scanner engine.
Run:  python server.py  (auto-relaunches with venv python if needed)
"""

import sys, os, subprocess

# ── Auto-relaunch with venv Python if on the wrong interpreter ─────────────
_HERE     = os.path.dirname(os.path.abspath(__file__))   # dashboard/
_ROOT     = os.path.dirname(_HERE)                        # new/
_VENV_PY  = os.path.join(_ROOT, "venv", "Scripts", "python.exe")
_VENV_SP  = os.path.join(_ROOT, "venv", "Lib", "site-packages")

def _using_venv():
    return os.path.abspath(sys.executable) == os.path.abspath(_VENV_PY)

if not _using_venv() and os.path.exists(_VENV_PY):
    print(f"[launcher] Switching to venv Python: {_VENV_PY}")
    result = subprocess.run([_VENV_PY] + sys.argv)
    sys.exit(result.returncode)

for _p in [_ROOT, _VENV_SP]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


from flask import Flask, request, jsonify, send_from_directory
import json

app = Flask(__name__, static_folder=".", static_url_path="")


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/scan", methods=["OPTIONS"])
def scan_preflight():
    return "", 204


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/scan", methods=["POST"])
def scan_endpoint():
    data = request.get_json(force=True)
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400
    try:
        from v2 import scan
        result = scan(prompt)
        return jsonify(result)
    except Exception as exc:
        import traceback
        return jsonify({"error": str(exc), "trace": traceback.format_exc()}), 500


# ── HuggingFace Inference API helper ─────────────────────────────────────────
# Completely free — sign up at huggingface.co → Settings → Access Tokens → New token
# Token format: hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

_HF_MODELS = [
    "openai/gpt-oss-120b:cerebras",                 # currently documented as live on Cerebras
    "openai/gpt-oss-120b:groq",                     # fallback on a different provider
    "meta-llama/Llama-3.1-8B-Instruct:cerebras",    # fallback, smaller model
]

def _call_hf(api_key, model, prompt_text, max_tokens=2048, timeout=60):
    """
    Call HuggingFace's unified Inference Providers router.
    Uses the `requests` library instead of urllib — some providers behind
    the router (Together, Cerebras) run Cloudflare bot protection that
    blocks raw urllib's TLS fingerprint with a 1010 error. requests/urllib3
    produces a different TLS handshake signature that isn't flagged.
    Returns (text, None) on success or (None, error_str) on failure.
    """
    import requests

    url = "https://router.huggingface.co/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": (
                "You are an expert cloud infrastructure-as-code engineer. "
                "Output ONLY raw IaC code — no markdown fences, no explanations."
            )},
            {"role": "user", "content": prompt_text},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
        if resp.status_code >= 400:
            detail = (resp.text or "").strip() or "(empty response body)"
            return None, f"HTTP {resp.status_code} {resp.reason}: {detail}"
        body = resp.json()
        text = body["choices"][0]["message"]["content"].strip()
        return text, None
    except requests.exceptions.Timeout:
        return None, "TimeoutError: The read operation timed out"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {e!r}"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}" if str(exc) else f"{type(exc).__name__} (no message)"


# ── POST /test-key ────────────────────────────────────────────────
@app.route("/test-key", methods=["OPTIONS"])
def test_key_preflight():
    return "", 204


@app.route("/test-key", methods=["POST"])
def test_key_endpoint():
    data    = request.get_json(force=True)
    raw_key = (data.get("gemini_api_key") or "").strip()
    api_key = "".join(raw_key.split())   # strip all internal whitespace
    if not api_key:
        return jsonify({"ok": False, "error": "No API key provided"}), 400

    if not api_key.startswith("hf_"):
        prefix = api_key[:6] if len(api_key) >= 6 else api_key
        return jsonify({
            "ok": False,
            "error": (
                f"That key starts with '{prefix}' — not a HuggingFace token. "
                f"Go to huggingface.co/settings/tokens → New token (Read) → copy the hf_... token."
            )
        }), 200

    print(f"[test-key] prefix={api_key[:8]}... len={len(api_key)}")

    last_err = "No models tried"
    for model in _HF_MODELS:
        text, err = _call_hf(api_key, model, "Reply with the single word: OK", max_tokens=10, timeout=20)
        if text is not None:
            print(f"[test-key] ✅ {model}")
            return jsonify({"ok": True, "model": model})
        last_err = err or "Unknown error"
        print(f"[test-key] ❌ {model}: {last_err}")
        if any(x in str(last_err).lower() for x in ["401", "403", "unauthorized", "invalid", "token"]):
            return jsonify({"ok": False, "error": last_err, "code": 401}), 200

    return jsonify({"ok": False, "error": last_err}), 200


# ── POST /generate-iac ────────────────────────────────────────────
@app.route("/generate-iac", methods=["OPTIONS"])
def gen_iac_preflight():
    return "", 204


@app.route("/generate-iac", methods=["POST"])
def generate_iac_endpoint():
    data    = request.get_json(force=True)
    prompt  = (data.get("prompt") or "").strip()
    lang    = (data.get("lang")   or "terraform").strip().lower()
    raw_key = (data.get("gemini_api_key") or "").strip()
    api_key = "".join(raw_key.split())

    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400
    if not api_key:
        return jsonify({"error": "No API key. Get a free token at huggingface.co/settings/tokens"}), 400

    print(f"[generate-iac] prefix={api_key[:8]}... lang={lang}")

    lang_labels = {
        "terraform":      "Terraform (.tf HCL)",
        "cloudformation": "AWS CloudFormation (YAML)",
        "pulumi":         "Pulumi (Python)",
        "ansible":        "Ansible Playbook (YAML)",
    }
    lang_label = lang_labels.get(lang, lang.capitalize())

    user_prompt = (
        f"Generate a complete, production-ready {lang_label} IaC script for:\n\n"
        f"{prompt}\n\n"
        f"Requirements:\n"
        f"- Encryption at rest and in transit\n"
        f"- Least-privilege IAM roles\n"
        f"- Logging and monitoring (CloudTrail/CloudWatch)\n"
        f"- Proper resource tagging\n"
        f"- Inline comments explaining security decisions\n"
        f"Output ONLY the raw {lang_label} code. No markdown fences. No explanations."
    )

    last_err = "No model succeeded"
    for model in _HF_MODELS:
        text, err = _call_hf(api_key, model, user_prompt, max_tokens=2048, timeout=90)
        if text is not None:
            if text.startswith("```"):
                lines = text.splitlines()
                text  = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])
            print(f"[generate-iac] ✅ {len(text)} chars via {model}")

            reality = {}
            try:
                import sys as _sys
                _sys.path.insert(0, _ROOT)
                from parse_reality import extract_and_save
                reality = extract_and_save(
                    iac_code        = text,
                    lang            = lang,
                    original_prompt = prompt,
                    model_used      = model,
                )
                print(f"[generate-iac] reality_received.json saved — "
                      f"{reality.get('resource_count', 0)} resources, "
                      f"{len(reality.get('issues_detected', []))} issues")
            except Exception as re_exc:
                print(f"[generate-iac] ⚠️  parse_reality failed: {re_exc}")

            return jsonify({
                "iac_script":      text,
                "model":           model,
                "lang":            lang,
                "reality_summary": reality.get("reality_summary", ""),
                "resource_count":  reality.get("resource_count", 0),
                "resource_list":   reality.get("resource_list", []),
                "issues_detected": reality.get("issues_detected", []),
            })

        last_err = err or "Unknown error"
        print(f"[generate-iac] ❌ {model}: {last_err}")
        if any(x in str(last_err).lower() for x in ["401", "403", "unauthorized", "invalid", "token"]):
            return jsonify({"error": f"API key error: {last_err}"}), 502

    return jsonify({"error": f"All models failed. Last: {last_err}"}), 502


if __name__ == "__main__":
    print("=" * 60)
    print("  Shadow AI IaC Security Dashboard — Backend")
    print("  Open  http://localhost:5000  in your browser")
    print("=" * 60)
    app.run(debug=True, port=5000)