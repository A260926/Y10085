const DIFF_CLASS = {
  identical: ["ok", "完全一致"],
  short_circuit_difference: ["info", "同结果不同短路路径"],
  access_trace_difference: ["info", "同结果不同字段轨迹"],
  decision_difference: ["bad", "决策结果不同"],
  status_detail_difference: ["warn", "异常细节不同"],
  status_difference: ["warn", "正常/异常状态不同"],
};
const VERDICTS = { accept: "接受", block: "阻止", exception: "限时例外" };
let rules = [], batches = [], currentBatch = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function json(o) { return JSON.stringify(o, null, 2); }
function flash(text, bad) {
  const el = document.getElementById("msg");
  el.style.borderColor = bad ? "var(--bad)" : "var(--warn)";
  el.textContent = text;
  el.style.display = "block";
  clearTimeout(flash._t);
  flash._t = setTimeout(() => (el.style.display = "none"), 8000);
}
async function api(method, url, body) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) opt.body = JSON.stringify(body);
  const res = await fetch(url, opt);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(typeof data === "object" ? JSON.stringify(data, null, 2) : String(data));
    err.payload = data;
    err.status = res.status;
    throw err;
  }
  return data;
}

async function loadRules() {
  rules = await api("GET", "/api/rules");
  for (const id of ["rule-parent", "batch-current", "batch-candidate"]) {
    const sel = document.getElementById(id);
    const keep = sel.value;
    sel.innerHTML = (id === "rule-parent" ? '<option value="">（无父版本）</option>' : "")
      + rules.map((r) => `<option value="${r.id}">${esc(r.name)} · ${r.digest.slice(0, 8)}</option>`).join("");
    if (keep) sel.value = keep;
  }
  if (rules.length >= 2 && !document.getElementById("batch-current").value) {
    document.getElementById("batch-current").value = rules[0].id;
    document.getElementById("batch-candidate").value = rules[1].id;
  }
}

async function uploadRule() {
  const name = document.getElementById("rule-name").value.trim();
  let rule;
  try {
    rule = JSON.parse(document.getElementById("rule-body").value);
  } catch (e) {
    flash("规则不是合法 JSON：" + e.message, true);
    return;
  }
  const parentSel = document.getElementById("rule-parent");
  try {
    const r = await api("POST", "/api/rules", {
      name,
      rule,
      parent_id: parentSel.value || null,
    });
    document.getElementById("rule-result").innerHTML =
      `已保存 id=<span class="mono">${esc(r.id.slice(0, 8))}</span>，`
      + `规范摘要 <span class="mono">${esc(r.digest.slice(0, 16))}…</span>`;
    await loadRules();
  } catch (e) {
    flash("上传被拒绝：\n" + (e.payload.detail || e.message), true);
  }
}

async function createBatch() {
  let requests;
  try {
    requests = JSON.parse(document.getElementById("batch-requests").value);
    if (!Array.isArray(requests) || !requests.length) throw new Error("必须是非空数组");
  } catch (e) {
    flash("请求数组非法：" + e.message, true);
    return;
  }
  const key = document.getElementById("batch-key").value.trim();
  const body = {
    idempotency_key: key || null,
    current_rule_id: document.getElementById("batch-current").value,
    candidate_rule_id: document.getElementById("batch-candidate").value,
    secret_paths: document.getElementById("batch-secrets").value
      .split(",").map((s) => s.trim()).filter(Boolean),
    requests: requests.map((request) => ({ request })),
  };
  try {
    const batch = await api("POST", "/api/batches", body);
    flash(batch.reused ? "幂等键命中：返回原有冻结批次，未重复追加结果。"
                       : "演算完成：输入已冻结。", false);
    await loadBatches();
    showBatch(batch.id);
  } catch (e) {
    if (e.status === 409 && e.payload.code === "idempotency_input_mismatch") {
      flash("冲突：幂等键相同但输入摘要不同。\n原摘要："
        + e.payload.existing_input_digest.slice(0, 16) + "…\n新摘要："
        + e.payload.submitted_input_digest.slice(0, 16) + "…", true);
    } else {
      flash("创建失败：" + (e.payload.detail || e.message), true);
    }
  }
}

async function loadBatches() {
  batches = await api("GET", "/api/batches");
  document.getElementById("batch-rows").innerHTML = batches.map((b) => {
    const s = b.summary || {};
    return `<tr class="req" onclick="showBatch('${b.id}')">
      <td class="mono">${esc(b.id.slice(0, 8))}</td>
      <td><span class="pill ${b.status === "done" ? "ok" : "warn"}">${b.status}</span></td>
      <td>v${b.revision}</td>
      <td>${s.differences ?? "-"}/${s.total ?? "-"}</td>
      <td class="muted">${esc(b.created_at || "")}</td>
      <td><button class="ghost" onclick="event.stopPropagation();showBatch('${b.id}')">查看</button></td>
    </tr>`;
  }).join("");
}

function sideView(title, o) {
  if (!o) return `<div class="box"><b>${esc(title)}</b><div class="muted">结果缺失（待恢复）</div></div>`;
  const pill = o.status === "ok"
    ? `<span class="pill ${o.value ? "ok" : "bad"}">${o.value ? "通过 true" : "拒绝 false"}</span>`
    : `<span class="pill warn">${esc(o.status)}：${esc(o.error || "")}</span>`;
  return `<div class="box"><b>${esc(title)}</b> ${pill}
    <div class="trace">访问字段：${o.accessed.map(esc).join(", ") || "（无）"}</div>
    <div class="trace">secret 存在性访问：${o.secret_access.map(esc).join(", ") || "（无）"}</div>
    <div class="trace">短路/异常路径：${esc(json(o.short_circuits))}</div></div>`;
}

function decisionView(item) {
  const d = item.decision;
  const curVersion = d ? d.version : 0;
  const stamp = new Date().toISOString().slice(0, 16);
  const exp = d && d.verdict === "exception"
    ? `<span class="verdict-exception">至 ${esc(d.expires_at)} ${d.active ? "生效中" : "已到期"}</span>`
    : "";
  const existing = d
    ? `<div class="muted">当前决议：<b class="verdict-${d.verdict}">${VERDICTS[d.verdict]}</b>
        ${exp} <span class="mono">${esc(d.reason)}</span>（版本 v${d.batch_revision}）</div>`
    : `<div class="muted">尚无决议（提交版本 v0）</div>`;
  return `<div class="decision-row">
      ${existing}
      <select id="verdict-${item.request_id}">
        <option value="accept">接受</option>
        <option value="block">阻止</option>
        <option value="exception">限时例外</option>
      </select>
      <input id="reason-${item.request_id}" placeholder="决议理由（双方冲突时各自保留）">
      <input id="expires-${item.request_id}" type="datetime-local" value="${stamp}"
        title="限时例外到期时间（UTC）">
      <input type="hidden" id="version-${item.request_id}" value="${curVersion}">
      <button onclick="submitDecision('${currentBatch.id}','${item.request_id}')">提交决议</button>
    </div>`;
}

function renderBatch(batch) {
  currentBatch = batch;
  document.getElementById("detail-card").style.display = "block";
  document.getElementById("batch-meta").innerHTML =
    `批次 <span class="mono">${esc(batch.id)}</span> · 修订 <b>v${batch.revision}</b> · `
    + `${esc(batch.status)} · 输入摘要 <span class="mono">${esc(batch.input_digest.slice(0, 20))}…</span>`
    + (batch.idempotency_key ? ` · 幂等键 <span class="mono">${esc(batch.idempotency_key)}</span>` : "");
  document.getElementById("request-list").innerHTML = batch.requests.map((item) => {
    const [cls, label] = DIFF_CLASS[item.diff_category] || ["warn", item.diff_category || "待计算"];
    return `<div class="card">
      <b>#${item.position} <span class="pill ${cls}">${esc(label)}</span></b>
      <span class="muted mono"> ${esc(item.request_digest.slice(0, 12))}…</span>
      <details><summary class="muted">脱敏请求</summary><pre class="mono">${esc(json(item.redacted_request))}</pre></details>
      <div class="side">${sideView("当前版本", item.current)}${sideView("候选版本", item.candidate)}</div>
      <div class="muted" style="margin-top:6px">
        ${esc(item.explanations ? item.explanations.current : "")} ｜
        ${esc(item.explanations ? item.explanations.candidate : "")}</div>
      ${decisionView(item)}
    </div>`;
  }).join("");
}

async function showBatch(id) {
  try {
    renderBatch(await api("GET", `/api/batches/${id}`));
  } catch (e) {
    flash(e.payload.detail || e.message, true);
  }
}

async function submitDecision(batchId, requestId) {
  const verdict = document.getElementById(`verdict-${requestId}`).value;
  const reason = document.getElementById(`reason-${requestId}`).value.trim();
  const expiresRaw = document.getElementById(`expires-${requestId}`).value;
  const version = Number(document.getElementById(`version-${requestId}`).value);
  if (!reason) { flash("决议必须填写理由", true); return; }
  const expires_at = verdict === "exception"
    ? new Date(expiresRaw).toISOString() : null;
  try {
    await api("PUT", `/api/batches/${batchId}/requests/${requestId}/decision`,
      { verdict, reason, expires_at, version });
    flash("决议已记录（绑定本批次修订，规则重传不会自动沿用）", false);
    await showBatch(batchId);
  } catch (e) {
    if (e.status === 409 && e.payload.code === "decision_version_conflict") {
      const ex = e.payload.existing_decision;
      flash("决议版本冲突！\n对方（v" + e.payload.required_version + "）："
        + (ex ? `${VERDICTS[ex.verdict] || ex.verdict} — ${ex.reason}` : "（无）")
        + `\n你方（v${e.payload.submitted_version}）：${e.payload.submitted_verdict} — ${e.payload.submitted_reason}`
        + "\n请刷新获取最新版本后重试。", true);
      await showBatch(batchId);
    } else {
      flash(e.payload.detail || e.message, true);
    }
  }
}

async function exportBatch() {
  if (!currentBatch) return;
  const data = await api("GET", `/api/batches/${currentBatch.id}/export`);
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `shadow-batch-${currentBatch.id.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

(async function init() {
  await loadRules();
  await loadBatches();
  if (batches.length) showBatch(batches[0].id);
})();
