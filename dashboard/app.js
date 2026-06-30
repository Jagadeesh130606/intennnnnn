/**
 * app.js — Shadow AI IaC Security Dashboard
 * Handles: prompt scan, intent display, IaC input, placeholder sections
 */

"use strict";

/* ── State ─────────────────────────────────────────── */
const ALL_RISK_THRESHOLD = 0.25; // auto-generate IaC only when ALL scores < 25%

const State = {
  scanResult:         null,
  scanPassed:         false,
  iacText:            "",
  iacLang:            "terraform",
  iacSubmitted:       false,
  iacAutoTriggered:   false, // true = Groq was auto-called after scan passed <25%
  sanitizedPrompt:    "",    // stored after scan for Groq generation
};

/* ── DOM helpers ───────────────────────────────────── */
const $  = id => document.getElementById(id);
const show = id => document.getElementById(id)?.classList.remove("hidden");
const hide = id => document.getElementById(id)?.classList.add("hidden");

/* ── Character counter ─────────────────────────────── */
const promptInput = $("prompt-input");
promptInput?.addEventListener("input", () => {
  const n = promptInput.value.length;
  $("char-count").textContent = `${n.toLocaleString()} character${n !== 1 ? "s" : ""}`;
});

/* ══════════════════════════════════════════════════════
   STEP TRACKER
══════════════════════════════════════════════════════ */
function setStep(num, status /* "active"|"done"|"error" */) {
  const el = $(`step-${num}-track`);
  if (!el) return;
  el.classList.remove("active", "done", "error");
  el.classList.add(status);
  // Update step number icon for done state
  const numEl = el.querySelector(".step-num");
  if (numEl && status === "done")  numEl.textContent = "✓";
  if (numEl && status === "error") numEl.textContent = "✗";
}

function setPipelineStatus(state /* "idle"|"running"|"success"|"error" */, label) {
  const dot  = document.querySelector(".status-dot");
  const text = document.querySelector(".status-text");
  if (!dot || !text) return;
  dot.className  = `status-dot ${state}`;
  text.textContent = label;
}

/* ══════════════════════════════════════════════════════
   TOAST
══════════════════════════════════════════════════════ */
function toast(msg, type = "info") {
  const icons = { success: "✅", error: "❌", info: "ℹ️" };
  const container = $("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${msg}</span>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* ══════════════════════════════════════════════════════
   LOADING OVERLAY
══════════════════════════════════════════════════════ */
function showLoading(title, sub) {
  $("loading-title").textContent = title;
  $("loading-sub").textContent   = sub;
  $("loading-overlay").classList.remove("hidden");
}
function hideLoading() {
  $("loading-overlay").classList.add("hidden");
}

/* ══════════════════════════════════════════════════════
   PHASE 1 — RUN PROMPT SCAN
══════════════════════════════════════════════════════ */
async function runScan() {
  const prompt = promptInput?.value?.trim();
  if (!prompt) {
    toast("Please enter a prompt first.", "error");
    return;
  }

  // UI feedback
  setPipelineStatus("running", "Scanning…");
  showLoading("Running Prompt Scanner…", "LLM Guard: PII · Secrets · Injection check");
  setStep(1, "active");

  try {
    const res = await fetch("http://localhost:5000/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ prompt }),
    });

    const data = await res.json();

    if (!res.ok || data.error) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    State.scanResult = data;
    State.scanPassed = data.safe_to_proceed === true;

    renderScanResults(data);
    renderIntentExtractor(data);

    setStep(1, "done");
    setStep(2, "done");

    // Store sanitized prompt for IaC generation
    State.sanitizedPrompt = data.sanitized_prompt || data.raw_prompt || "";

    if (State.scanPassed) {
      setPipelineStatus("success", "Scan Passed");
      setStep(3, "active");
      unlockIacPhase();

      // Check if all risk scores are below threshold → auto-trigger Groq
      const scores  = data.scores || {};
      const allLow  = Object.values(scores).every(s => (typeof s === "number" ? s : 0) < ALL_RISK_THRESHOLD);
      if (allLow) {
        toast("All risks < 25% ✅ — auto-generating IaC script via Gemini!", "success");
        checkAndAutoGenerateIac();
      } else {
        toast("Prompt scan passed! Enter your Gemini API key to generate IaC, or paste manually.", "success");
      }
    } else {
      setPipelineStatus("error", "Issues Found");
      toast("Scan flagged issues — review warnings before proceeding.", "error");
    }

    markCheckItem("check-scan",   State.scanPassed);
    markCheckItem("check-intent", true);

  } catch (err) {
    hideLoading();
    setPipelineStatus("error", "Error");
    setStep(1, "error");
    toast(`Scan failed: ${err.message}`, "error");
    console.error("Scan error:", err);
  } finally {
    hideLoading();
  }
}

/* ── Render scan results ───────────────────────────── */
function renderScanResults(data) {
  show("phase-scan-results");

  // Banner
  const banner = $("guard-banner");
  const iacBadge = data.iac_prompt_detected
    ? `<span style="margin-left:auto;font-size:.72rem;background:rgba(99,130,255,.15);border:1px solid rgba(99,130,255,.3);color:#a0b8ff;padding:3px 10px;border-radius:50px;white-space:nowrap">
         🏗️ IaC prompt detected — threshold: ${data.injection_threshold_used ?? "—"}
       </span>`
    : "";
  if (data.safe_to_proceed) {
    banner.className = "result-banner pass";
    banner.innerHTML = `✅ <strong>All checks passed</strong> — No PII, secrets, or injection detected ${iacBadge}`;
  } else {
    banner.className = "result-banner fail";
    const warnCount = (data.warnings || []).length;
    banner.innerHTML = `⛔ <strong>${warnCount} issue${warnCount !== 1 ? "s" : ""} found</strong> — Review warnings below before proceeding ${iacBadge}`;
  }

  // Scores grid
  const scoresGrid = $("scores-grid");
  scoresGrid.innerHTML = "";
  const scoreMap = {
    Anonymize:       { label: "PII / Anonymize", icon: "👤" },
    Secrets:         { label: "Secrets Leakage",  icon: "🔑" },
    PromptInjection: { label: "Prompt Injection", icon: "💉" },
  };
  const scores = data.scores || {};
  for (const [key, rawScore] of Object.entries(scores)) {
    const info   = scoreMap[key] || { label: key, icon: "🔍" };
    const score  = typeof rawScore === "number" ? rawScore : 0;
    const pct    = (score * 100).toFixed(1);
    const cls    = score < 0.3 ? "good" : score < 0.65 ? "warn" : "bad";
    const status = score < 0.3 ? "✅ Clean" : score < 0.65 ? "⚠️ Caution" : "❌ Flagged";
    scoresGrid.insertAdjacentHTML("beforeend", `
      <div class="score-card">
        <div class="score-name">${info.icon} ${info.label}</div>
        <div class="score-val ${cls}">${pct}%</div>
        <div class="score-status">${status}</div>
      </div>
    `);
  }

  // Warnings
  const warnings = data.warnings || [];
  if (warnings.length > 0) {
    show("warnings-section");
    const list = $("warnings-list");
    list.innerHTML = "";
    warnings.forEach(w => {
      const noteHtml = w.note
        ? `<div class="warning-detail" style="color:var(--accent-yellow);font-size:.75rem">ℹ️ ${w.note}</div>`
        : "";
      const threshHtml = w.threshold != null
        ? `<div class="warning-detail">Threshold: ${w.threshold} &nbsp;|&nbsp; Score: ${w.score}</div>`
        : `<div class="warning-detail">Score: ${w.score}</div>`;
      list.insertAdjacentHTML("beforeend", `
        <div class="warning-item">
          <div class="warning-scanner">⛔ [${w.severity || "HIGH"}] ${w.scanner}</div>
          ${threshHtml}
          <div class="warning-detail">→ ${w.action}</div>
          ${noteHtml}
        </div>
      `);
    });
  } else {
    hide("warnings-section");
  }

  // Sanitized prompt
  $("sanitized-prompt").textContent = data.sanitized_prompt || "(unchanged)";
}

/* ══════════════════════════════════════════════════════
   PHASE 2 — RENDER INTENT EXTRACTOR
══════════════════════════════════════════════════════ */
function renderIntentExtractor(data) {
  show("phase-intent");

  const schema = data.constraint_schema || {};

  /* Intent summary */
  const summaryEl = $("intent-summary-banner");
  summaryEl.textContent = data.intent_summary || "No clear IaC intent detected.";

  /* Intent grid cells */
  const grid = $("intent-grid");
  grid.innerHTML = "";

  const enc  = schema.encryption  || {};
  const iam  = schema.iam         || {};
  const avail= schema.availability || {};
  const log  = schema.logging     || {};
  const acc  = schema.access      || {};
  const reg  = schema.region      || {};

  const cells = [
    {
      label: "Region",
      val:   reg.code ? `${reg.code} — ${reg.name}` : "Not specified",
      icon:  "🌍",
    },
    {
      label: "Encryption",
      val:   enc.disabled
               ? `<span class="intent-pill pill-neg">❌ DISABLED</span>`
               : enc.enabled
                 ? `<span class="intent-pill pill-yes">✅ Enabled</span>`
                 : `<span class="intent-pill pill-no">— Not specified</span>`,
      note: enc.disabled ? buildNegNote(["disable", "without", "no"]) : "",
    },
    {
      label: "KMS",
      val: enc.kms
        ? `<span class="intent-pill pill-yes">✅ Requested</span>`
        : `<span class="intent-pill pill-no">— Not requested</span>`,
    },
    {
      label: "IAM Least-Privilege",
      val: iam.least_privilege
        ? `<span class="intent-pill pill-yes">✅ Yes</span>`
        : `<span class="intent-pill pill-no">— No</span>`,
    },
    {
      label: "Admin Access",
      val: iam.admin_access
        ? `<span class="intent-pill pill-neg">⚠️ Requested</span>`
        : `<span class="intent-pill pill-yes">✅ Not present</span>`,
    },
    {
      label: "Multi-AZ",
      val: avail.multi_az
        ? `<span class="intent-pill pill-yes">✅ Yes</span>`
        : `<span class="intent-pill pill-no">— No</span>`,
    },
    {
      label: "EC2 Count",
      val: avail.ec2_count != null
        ? `<span style="color:var(--accent-cyan)">${avail.ec2_count} instance(s)</span>`
        : `<span class="intent-pill pill-no">— Not specified</span>`,
    },
    {
      label: "Logging",
      val: log.enabled
        ? `<span class="intent-pill pill-yes">✅ Enabled</span>`
        : `<span class="intent-pill pill-no">— Not specified</span>`,
    },
    {
      label: "CloudTrail",
      val: log.cloudtrail
        ? `<span class="intent-pill pill-yes">✅ Yes</span>`
        : `<span class="intent-pill pill-no">— No</span>`,
    },
    {
      label: "SSH Configured",
      val: acc.ssh?.configured
        ? acc.ssh?.open_to_world
          ? `<span class="intent-pill pill-neg">⚠️ Open to world (0.0.0.0/0)</span>`
          : `<span class="intent-pill pill-yes">✅ Restricted</span>`
        : `<span class="intent-pill pill-no">— No</span>`,
    },
    {
      label: "Public S3",
      val: acc.public_s3
        ? `<span class="intent-pill pill-neg">⚠️ Public access detected</span>`
        : `<span class="intent-pill pill-yes">✅ Private</span>`,
    },
  ];

  cells.forEach(c => {
    grid.insertAdjacentHTML("beforeend", `
      <div class="intent-cell">
        <div class="intent-cell-label">${c.label}</div>
        <div class="intent-cell-val">${c.val}</div>
        ${c.note ? `<div style="margin-top:4px">${c.note}</div>` : ""}
      </div>
    `);
  });

  /* Conflicts */
  const conflicts = data.conflicts || [];
  if (conflicts.length > 0) {
    show("conflicts-section");
    const cl = $("conflicts-list");
    cl.innerHTML = "";
    conflicts.forEach(c => {
      cl.insertAdjacentHTML("beforeend", `<div class="conflict-item">⛔ ${c}</div>`);
    });
  } else {
    hide("conflicts-section");
  }

  /* Resources */
  const resources = data.expected_resources || [];
  const resEl = $("resources-list");
  resEl.innerHTML = "";
  if (resources.length) {
    resources.forEach(r => {
      resEl.insertAdjacentHTML("beforeend", `<span class="chip chip-blue">📦 ${r}</span>`);
    });
  } else {
    resEl.innerHTML = `<span class="chip chip-gray">None detected</span>`;
  }

  /* Compliance */
  const compliance = data.compliance || [];
  if (compliance.length) {
    show("compliance-section");
    const comEl = $("compliance-list");
    comEl.innerHTML = "";
    compliance.forEach(f => {
      comEl.insertAdjacentHTML("beforeend", `<span class="chip chip-green">✅ ${f}</span>`);
    });
  } else {
    hide("compliance-section");
  }

  /* Raw JSON */
  $("intent-json").textContent = JSON.stringify(data.constraint_schema || {}, null, 2);
}

/** Renders a small negation-keyword tooltip */
function buildNegNote(keywords) {
  const tags = keywords.map(k => `<span class="neg-keyword">${k}</span>`).join(" ");
  return `<div style="font-size:.7rem;color:var(--accent-yellow);margin-top:2px">Negation detected: ${tags}</div>`;
}

/* ══════════════════════════════════════════════════════
   PHASE 3 — IaC INPUT UNLOCK + GROQ GENERATION
══════════════════════════════════════════════════════ */
function unlockIacPhase() {
  show("phase-iac");
  show("phase-attack");
  show("phase-risk");
  show("phase-deploy");

  // Smooth scroll to IaC section
  setTimeout(() => {
    $("phase-iac")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 400);
}

/** Enable the Generate + Test buttons once a Gemini key is typed */
function onGroqKeyChange() {
  const key     = $("groq-api-key")?.value?.trim();
  const genBtn  = $("btn-generate-iac");
  const testBtn = $("btn-test-key");
  if (genBtn)  genBtn.disabled  = !key;
  if (testBtn) testBtn.disabled = !key;
  // Reset key status when user types
  const statusLine = $("key-status-line");
  if (statusLine) statusLine.classList.add("hidden");
}

/** Quick-test the Gemini API key — shows exact error in the UI */
async function testGeminiKey() {
  const key     = $("groq-api-key")?.value?.trim();
  const testBtn = $("btn-test-key");
  const statusLine = $("key-status-line");

  if (!key) { toast("Please enter your API key first.", "error"); return; }

  if (testBtn) { testBtn.disabled = true; testBtn.textContent = "⏳ Testing…"; }
  if (statusLine) statusLine.classList.add("hidden");

  try {
    const res  = await fetch("http://localhost:5000/test-key", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ gemini_api_key: key }),
    });
    const data = await res.json();

    statusLine.classList.remove("hidden");

    if (data.ok) {
      statusLine.style.background = "rgba(62,207,142,.1)";
      statusLine.style.border     = "1px solid rgba(62,207,142,.3)";
      statusLine.style.color      = "#3ecf8e";
      statusLine.innerHTML        = "✅ API key is valid! Gemini (gemini-1.5-flash) responded successfully.";
      toast("API key works! Now click ✨ Generate IaC.", "success");
      const genBtn = $("btn-generate-iac");
      if (genBtn) genBtn.disabled = false;
    } else {
      const errMsg = data.error || "Unknown error";
      statusLine.style.background = "rgba(255,77,106,.1)";
      statusLine.style.border     = "1px solid rgba(255,77,106,.3)";
      statusLine.style.color      = "#ff8fa0";

      // Give user-friendly advice based on error
      let advice = "";
      if (data.code === 400 || (errMsg||"").includes("API_KEY_INVALID")) {
        advice = " → Your key looks wrong. Make sure you copied the full <code style='color:#a0cfff'>AIzaSy...</code> key from aistudio.google.com";
      } else if (data.code === 403 || (errMsg||"").includes("PERMISSION_DENIED")) {
        advice = " → API not enabled. In AI Studio, click <b>Enable API</b> after creating the key.";
      } else if ((errMsg||"").toLowerCase().includes("location") || (errMsg||"").includes("USER_LOCATION")) {
        advice = " → Your region may be restricted. Try using a VPN or contact Google.";
      } else if (data.code === 429) {
        advice = " → Rate limit hit. Wait a minute and try again.";
      }

      statusLine.innerHTML = `❌ <b>Error:</b> ${errMsg}${advice}`;
      toast(`Key test failed: ${errMsg}`, "error");
    }
  } catch (err) {
    if (statusLine) {
      statusLine.classList.remove("hidden");
      statusLine.style.background = "rgba(255,77,106,.1)";
      statusLine.style.border     = "1px solid rgba(255,77,106,.3)";
      statusLine.style.color      = "#ff8fa0";
      statusLine.innerHTML        = `❌ Could not reach server: ${err.message}. Is your Flask server running?`;
    }
    toast(`Connection error: ${err.message}`, "error");
  } finally {
    if (testBtn) { testBtn.disabled = false; testBtn.textContent = "🔍 Test Key"; }
    onGroqKeyChange();
  }
}

/** Called automatically when all scores < 25%, after phase-iac is shown */
function checkAndAutoGenerateIac() {
  const key = $("groq-api-key")?.value?.trim();
  const banner = $("iac-gen-banner");
  if (banner) banner.classList.remove("hidden");

  if (!key) {
    // Show banner asking for key, but don't block
    _setIacBanner("🔑", "Enter your free Gemini API key above to auto-generate the IaC script.");
    return;
  }
  generateIacFromGroq();
}

function _setIacBanner(icon, label, color) {
  const banner = $("iac-gen-banner");
  if (banner) banner.classList.remove("hidden");
  const ic = $("iac-gen-icon");  if (ic) ic.textContent = icon;
  const lb = $("iac-gen-label"); if (lb) lb.textContent = label;
  if (color && banner) banner.style.borderColor = color;
}

/** Calls POST /generate-iac and fills the textarea with the result */
async function generateIacFromGroq() {
  const key    = $("groq-api-key")?.value?.trim();
  const prompt = State.sanitizedPrompt || promptInput?.value?.trim();

  if (!key) {
    toast("Please enter your Groq API key first.", "error");
    return;
  }
  if (!prompt) {
    toast("No prompt available — run the scan first.", "error");
    return;
  }

  const btn = $("btn-generate-iac");
  if (btn) { btn.disabled = true; btn.innerHTML = `<span class="btn-icon">⏳</span> Generating…`; }
  _setIacBanner("⏳", "Gemini (gemini-2.0-flash) is generating your IaC script — this may take 10–20s…", "rgba(250,180,60,.4)");
  showLoading("Generating IaC Script…", "Google Gemini · gemini-2.0-flash (free tier)");

  try {
    const res = await fetch("http://localhost:5000/generate-iac", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        prompt:          prompt,
        lang:            State.iacLang,
        gemini_api_key:  key,
      }),
    });

    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);

    const ta = $("iac-input");
    if (ta) ta.value = data.iac_script || "";
    State.iacText = data.iac_script || "";
    State.iacAutoTriggered = true;

    // Show source badge
    const badge = $("iac-source-badge");
    if (badge) {
      badge.textContent = `✨ AI-generated · ${State.iacLang}`;
      badge.classList.remove("hidden");
    }

    _setIacBanner("✅", `IaC script generated by Gemini (gemini-2.0-flash). Review it, then click Submit for Audit.`, "rgba(62,207,142,.4)");
    $("iac-footer-note").innerHTML = `<span class="note-icon">✨</span> Auto-generated by Groq AI — review before submitting.`;
    toast("IaC script generated! Review and submit for audit.", "success");

  } catch (err) {
    _setIacBanner("❌", `Generation failed: ${err.message} — you can paste the script manually.`, "rgba(255,80,80,.4)");
    toast(`IaC generation failed: ${err.message}`, "error");
    console.error("IaC gen error:", err);
  } finally {
    hideLoading();
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<span class="btn-icon">✨</span> Generate IaC`;
      onGroqKeyChange(); // re-check key
    }
  }
}

function selectLang(btn) {
  document.querySelectorAll(".lang-tab").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  State.iacLang = btn.dataset.lang;
}

function clearIac() {
  const ta = $("iac-input");
  if (ta) ta.value = "";
  State.iacText = "";
}

function submitIac() {
  const ta = $("iac-input");
  const text = ta?.value?.trim();
  if (!text) {
    toast("Please paste your IaC script first.", "error");
    return;
  }
  State.iacText     = text;
  State.iacSubmitted = true;

  // Visual feedback on the button
  const btn = $("btn-iac-submit");
  if (btn) {
    btn.innerHTML = `<span class="btn-icon">✅</span> IaC Script Submitted`;
    btn.disabled  = true;
    btn.style.background = "linear-gradient(135deg,#1a8c5a 0%,#3ecf8e 100%)";
  }

  markCheckItem("check-iac", true);
  setStep(3, "done");
  toast(`${State.iacLang.toUpperCase()} script received — ready for audit pipeline.`, "success");

  // Scroll to attack graph placeholder
  setTimeout(() => $("phase-attack")?.scrollIntoView({ behavior: "smooth", block: "start" }), 400);
}

/* ══════════════════════════════════════════════════════
   CHECKLIST HELPERS
══════════════════════════════════════════════════════ */
function markCheckItem(id, passed) {
  const el = $(id);
  if (!el) return;
  el.classList.remove("pending", "done", "fail");
  if (passed) {
    el.classList.add("done");
    el.querySelector(".check-icon").textContent = "✅";
  } else {
    el.classList.add("fail");
    el.querySelector(".check-icon").textContent = "❌";
  }
}

/* ══════════════════════════════════════════════════════
   INIT
══════════════════════════════════════════════════════ */
document.addEventListener("DOMContentLoaded", () => {
  // Reveal the first phase
  show("phase-prompt");
  setStep(1, "active");
  setPipelineStatus("idle", "Idle");
});
