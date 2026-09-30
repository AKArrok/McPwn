/* All records below are illustrative, not live scan results. */
const targets = [
  {
    name: "实验 MCP · 资源服务",
    endpoint: "http://127.0.0.1:9001/sse",
    transport: "SSE",
    tags: "本地靶场 · 资源",
    scan: "已完成",
  },
  {
    name: "实验 MCP · 文件服务",
    endpoint: "http://127.0.0.1:9003/sse",
    transport: "SSE",
    tags: "本地靶场 · 文件",
    scan: "无定论",
  },
  {
    name: "Excel MCP · 漏洞版示例",
    endpoint: "http://127.0.0.1:9203/sse",
    transport: "SSE",
    tags: "版本对照 · 文件",
    scan: "已完成",
  },
  {
    name: "Excel MCP · 修复版示例",
    endpoint: "http://127.0.0.1:9204/sse",
    transport: "SSE",
    tags: "版本对照 · 负向",
    scan: "已取消",
  },
];
const runs = [
  {
    id: "DEMO-005",
    target: targets[2].name,
    status: "completed",
    time: "今天 14:32",
    elapsed: "1分 42秒",
    tokens: "8,420",
    candidates: "4 / 4",
    findings: 2,
    stop: "completed",
    profile: "均衡",
    stages: 5,
  },
  {
    id: "DEMO-004",
    target: targets[3].name,
    status: "cancelled",
    time: "今天 14:15",
    elapsed: "24秒",
    tokens: "1,280",
    candidates: "1 / 4",
    findings: 0,
    stop: "user_cancelled",
    profile: "均衡",
    stages: 2,
  },
  {
    id: "DEMO-003",
    target: targets[1].name,
    status: "inconclusive",
    time: "今天 13:48",
    elapsed: "2分 00秒",
    tokens: "9,610",
    candidates: "3 / 6",
    findings: 0,
    stop: "budget_wall",
    profile: "深入",
    stages: 3,
  },
  {
    id: "DEMO-002",
    target: targets[0].name,
    status: "completed",
    time: "今天 13:20",
    elapsed: "58秒",
    tokens: "4,730",
    candidates: "3 / 3",
    findings: 1,
    stop: "completed",
    profile: "快速",
    stages: 5,
  },
  {
    id: "DEMO-001",
    target: targets[1].name,
    status: "failed",
    time: "昨天 17:09",
    elapsed: "8秒",
    tokens: "0",
    candidates: "0 / ?",
    findings: 0,
    stop: "connection_failed",
    profile: "快速",
    stages: 0,
  },
];
const findings = [
  {
    id: "DEMO-F01",
    title: "文件路径可能越过沙箱边界",
    severity: "高",
    vuln: "path_traversal",
    target: targets[2].name,
    tool: "read_data_from_excel",
    confidence: "0.94",
    run: "DEMO-005",
    time: "今天 14:33",
    signal: "sandbox_escape_read",
    evidence:
      "示例返回结果中，实际文件路径位于配置的 sandbox_root 之外，并返回了测试标记。",
    remediation:
      "在服务端解析并规范化文件路径，校验最终路径位于允许的沙箱根目录内。读写操作应使用同一套路径校验。",
    trace: ["create_workbook", "write_data_to_excel", "read_data_from_excel"],
  },
  {
    id: "DEMO-F02",
    title: "绝对路径写入缺少边界校验",
    severity: "中",
    vuln: "path_traversal",
    target: targets[2].name,
    tool: "write_data_to_excel",
    confidence: "0.75",
    run: "DEMO-005",
    time: "今天 14:33",
    signal: "sandbox_escape_write",
    evidence: "示例调用接受了沙箱外绝对路径。该返回需要进一步重放和落盘核验。",
    remediation:
      "拒绝绝对路径并进行根目录约束，避免只检查字符串前缀。对符号链接和路径规范化结果做一致校验。",
    trace: ["create_workbook", "write_data_to_excel"],
  },
  {
    id: "DEMO-F03",
    title: "资源返回中出现敏感信息信号",
    severity: "高",
    vuln: "direct_prompt_injection",
    target: targets[0].name,
    tool: "read_resource",
    confidence: "0.87",
    run: "DEMO-002",
    time: "今天 13:21",
    signal: "sensitive_resource_content",
    evidence:
      "示例资源返回中出现了被识别为敏感字段的内容，展示区域应复用去密逻辑。",
    remediation:
      "按调用者身份控制资源访问。将敏感配置与公开资源分离，并避免工具描述诱导模型获取无关资源。",
    trace: ["list_resources", "read_resource"],
  },
];
const labels = {
  completed: "已完成",
  cancelled: "已取消",
  inconclusive: "无定论",
  failed: "失败",
};
const pages = {
  overview: "总览",
  targets: "目标",
  runs: "运行记录",
  findings: "发现项",
  "new-scan": "新建扫描",
  offline: "离线导入",
};
let selectedRun = runs[0].id,
  selectedFinding = findings[0].id;
const $ = (id) => document.getElementById(id);
function node(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = String(text);
  return n;
}
function append(parent, ...children) {
  parent.append(...children);
  return parent;
}
function badge(text, cls = "") {
  return node("span", `badge ${cls}`, text);
}
function keyValues(entries) {
  const box = node("div", "key-values");
  for (const [label, value] of entries)
    box.append(
      append(
        node("div", "key-value"),
        node("span", "", label),
        node("strong", "", value),
      ),
    );
  return box;
}
function section(title, text) {
  return append(
    node("section", "detail-section"),
    node("h3", "", title),
    node("p", "", text),
  );
}
function setPage(page, updateLocation = true) {
  if (!Object.hasOwn(pages, page)) page = "overview";
  document
    .querySelectorAll(".page")
    .forEach((n) => n.classList.toggle("active", n.id === `page-${page}`));
  document.querySelectorAll(".nav-link").forEach((n) => {
    const active = n.dataset.page === page;
    n.classList.toggle("active", active);
    if (active) n.setAttribute("aria-current", "page");
    else n.removeAttribute("aria-current");
  });
  $("breadcrumb-page").textContent = pages[page];
  if (updateLocation && location.hash !== `#${page}`)
    history.pushState(null, "", `#${page}`);
  window.scrollTo(0, 0);
}
document.querySelectorAll("[data-page]").forEach((n) => {
  n.setAttribute("aria-label", pages[n.dataset.page]);
  n.addEventListener("click", () => setPage(n.dataset.page));
});
document.querySelectorAll(".eyebrow,.panel-kicker").forEach((n) => {
  const captions = {
    "WORKSPACE / OVERVIEW": "工作空间 / 总览",
    "RECENT ACTIVITY": "近期活动",
    "EVIDENCE FIRST": "证据优先",
    SCOPE: "评估范围",
    "ASSET INVENTORY": "目标清单",
    "EXECUTION HISTORY": "执行历史",
    "EVIDENCE REVIEW": "证据复核",
    "NEW ASSESSMENT": "创建评估",
    "OFFLINE ARTIFACT": "离线产物",
    "LOCAL ONLY": "仅本地读取",
  };
  n.textContent = captions[n.textContent] || n.textContent;
});
function runRow(run, selected = false) {
  const button = node("button", `run-row${selected ? " selected" : ""}`);
  button.type = "button";
  button.setAttribute("aria-pressed", String(selected));
  append(
    button,
    node(
      "span",
      `row-icon ${run.status === "completed" ? "" : "gray"}`,
      run.status === "completed" ? "✓" : "—",
    ),
    append(
      node("span", "row-main"),
      node("strong", "", run.target),
      node("small", "", `${run.id} · ${run.profile} · ${run.time}`),
    ),
    append(
      node("span", "row-end"),
      badge(labels[run.status], run.status),
      node("small", "", `${run.elapsed} · ${run.findings} 项发现`),
    ),
  );
  button.addEventListener("click", () => {
    if (!button.closest("#run-list")) {
      $("run-search").value = "";
      $("run-status").value = "";
    }
    selectedRun = run.id;
    renderRuns();
    setPage("runs");
  });
  return button;
}
const metrics = [
  ["登记目标", targets.length, "4 个本地授权入口", "accent"],
  ["疑似发现", findings.length, "尚未经过独立真实重放", "warning"],
  ["已验证", 0, "需要重放成功与审计证据", ""],
  ["运行无定论", 1, "预算终止 · 不等于安全", ""],
];
metrics.forEach(([label, value, note, cls]) =>
  $("metrics").append(
    append(
      node("div", `metric ${cls}`),
      node("div", "metric-label", label),
      node("div", "metric-number", value),
      node("div", "metric-note", note),
    ),
  ),
);
runs.slice(0, 4).forEach((r) => $("overview-runs").append(runRow(r)));
[
  ["疑似 · 未重放", 3, ""],
  ["已验证", 0, "verified"],
  ["重放失败", 0, "inconclusive"],
].forEach(([label, count, cls]) =>
  $("status-breakdown").append(
    append(
      node("div", "status-line"),
      node("span", `status-dot ${cls}`),
      node("span", "", label),
      node("strong", "", count),
    ),
  ),
);
targets.forEach((t) =>
  $("scope-list").append(
    append(
      node("div", "scope-item"),
      node("span", "", t.name.replace(" · ", " / ")),
      node("small", "", t.scan),
    ),
  ),
);
$("target-count").textContent = `${targets.length} 个目标`;
targets.forEach((t) => {
  const row = node("tr");
  append(
    row,
    append(node("td"), node("strong", "", t.name), node("small", "", t.tags)),
    append(node("td"), badge(t.transport)),
    append(node("td"), node("code", "", t.endpoint)),
    append(node("td"), badge("示例：可连接")),
    node("td", "", t.scan),
  );
  $("target-table").append(row);
});
function renderRuns() {
  const query = $("run-search").value.trim().toLowerCase(),
    status = $("run-status").value;
  const list = runs.filter(
    (r) =>
      (!status || r.status === status) &&
      `${r.target} ${r.id}`.toLowerCase().includes(query),
  );
  if (!list.some((r) => r.id === selectedRun)) selectedRun = list[0]?.id;
  $("run-list").replaceChildren(
    ...list.map((r) => runRow(r, r.id === selectedRun)),
  );
  if (!list.length)
    $("run-list").append(node("div", "empty-state", "没有匹配的运行记录"));
  $("run-count").textContent =
    `显示 ${list.length} / ${runs.length} 条演示记录`;
  const run = list.find((r) => r.id === selectedRun);
  const detail = $("run-detail");
  detail.replaceChildren();
  if (!run) {
    detail.append(
      node("div", "empty-state", "没有可显示的运行详情，请调整筛选。"),
    );
    return;
  }
  append(
    detail,
    append(
      node("div", "detail-kicker"),
      node("span", "", run.id),
      badge("演示记录"),
    ),
    node("h2", "", run.target),
    node("p", "detail-subtitle", `${run.time} · ${run.profile}扫描`),
    badge(labels[run.status], run.status),
    keyValues([
      ["耗时", run.elapsed],
      ["已用 token", run.tokens],
      ["候选完成数", run.candidates],
      ["停止原因", run.stop],
    ]),
  );
  const phases = section(
    "真实阶段",
    "阶段只根据执行事件推进；未知总量显示 ?。",
  );
  const track = node("div", "stage-track");
  for (let i = 0; i < 5; i++)
    track.append(node("span", i < run.stages ? "done" : ""));
  phases.append(
    track,
    append(
      node("div", "stage-labels"),
      ...["侦察", "规划", "执行", "验证", "报告"].map((s) =>
        node("span", "", s),
      ),
    ),
  );
  detail.append(
    phases,
    section(
      "运行结论",
      run.status === "completed"
        ? `示例运行正常结束，产生 ${run.findings} 个疑似发现。完成状态只说明流程结束。`
        : run.status === "inconclusive"
          ? "示例运行触发 wall-time 预算。仍有候选未完成，不能据此给出安全结论。"
          : run.status === "cancelled"
            ? "示例运行由用户取消。已经产生的证据应保留，未完成的部分不作结论。"
            : "示例在连接阶段失败。应显示去密后的错误摘要和错误码。",
    ),
  );
}
function renderFindings() {
  const q = $("finding-search").value.trim().toLowerCase(),
    severity = $("finding-severity").value;
  const list = findings.filter(
    (f) =>
      (!severity || f.severity === severity) &&
      `${f.title} ${f.vuln} ${f.target} ${f.tool}`.toLowerCase().includes(q),
  );
  if (!list.some((f) => f.id === selectedFinding))
    selectedFinding = list[0]?.id;
  $("finding-count").textContent = `${list.length} 项`;
  const items = list.map((f) => {
    const b = node(
      "button",
      `finding-row${f.id === selectedFinding ? " selected" : ""}`,
    );
    b.type = "button";
    b.setAttribute("aria-pressed", String(f.id === selectedFinding));
    append(
      b,
      append(
        node("span", "finding-row-top"),
        badge(`${f.severity}危`, f.severity === "高" ? "high" : "medium"),
        node("strong", "", f.title),
      ),
      append(
        node("span", "finding-row-meta"),
        node("span", "", f.tool),
        node("span", "", `疑似 · ${f.confidence}`),
      ),
    );
    b.addEventListener("click", () => {
      selectedFinding = f.id;
      renderFindings();
    });
    return b;
  });
  $("finding-list").replaceChildren(...items);
  if (!items.length)
    $("finding-list").append(node("div", "empty-state", "没有匹配的发现项"));
  const f = list.find((x) => x.id === selectedFinding),
    detail = $("finding-detail");
  detail.replaceChildren();
  if (!f) {
    detail.append(
      node("div", "empty-state", "没有可显示的发现项详情，请调整筛选。"),
    );
    return;
  }
  append(
    detail,
    append(
      node("div", "detail-kicker"),
      node("span", "", f.id),
      badge("演示证据"),
    ),
    node("h2", "", f.title),
    node("p", "detail-subtitle", f.target),
    append(
      node("div", "detail-tags"),
      badge(`${f.severity}危`, f.severity === "高" ? "high" : "medium"),
      badge("疑似 · 尚未重放", "suspected"),
    ),
    keyValues([
      ["漏洞类别", f.vuln],
      ["置信度", f.confidence],
      ["来源运行", f.run],
      ["发现时间", f.time],
    ]),
  );
  const evidence = section("命中证据", "以下文字用于展示证据的阅读层级。");
  evidence.append(
    append(
      node("div", "evidence-block"),
      node("strong", "", f.signal),
      node("p", "", f.evidence),
    ),
  );
  detail.append(evidence);
  const trace = node("section", "detail-section");
  trace.append(node("h3", "", "调用序列"));
  f.trace.forEach((tool, i) =>
    trace.append(
      append(
        node("div", "trace-step"),
        node("span", "trace-index", i + 1),
        append(
          node("div"),
          node("span", "", tool),
          node("small", "", `source_call_index: ${i} · 示例调用`),
        ),
      ),
    ),
  );
  detail.append(trace, section("处置建议", f.remediation));
  const raw = node("details");
  append(
    raw,
    node("summary", "", "展开原始返回（示例）"),
    node(
      "pre",
      "",
      JSON.stringify(
        {
          demo: true,
          tool: f.tool,
          result_text: "示例返回文本；真实数据必须经过统一去密。",
        },
        null,
        2,
      ),
    ),
  );
  detail.append(
    raw,
    section("验证状态", "尚未重放。此预览未连接后端，重放操作不可用。"),
  );
}
["run-search", "run-status"].forEach((id) =>
  $(id).addEventListener("input", renderRuns),
);
["finding-search", "finding-severity"].forEach((id) =>
  $(id).addEventListener("input", renderFindings),
);
targets.forEach((t, i) => {
  const opt = node("option", "", t.name);
  opt.value = String(i);
  $("scan-target").append(opt);
});
const presets = {
  quick: ["快速", "6,000 token", "60 秒", "3 个候选", "3 步 / 候选"],
  balanced: ["均衡", "20,000 token", "180 秒", "8 个候选", "6 步 / 候选"],
  deep: ["深入", "40,000 token", "300 秒", "12 个候选", "10 步 / 候选"],
};
let preset = "quick";
function renderBudget() {
  const b = presets[preset];
  $("budget-summary").replaceChildren(
    keyValues([
      ["目标", targets[Number($("scan-target").value)].name],
      ["强度", b[0]],
      ["token 上限", b[1]],
      ["运行时间上限", b[2]],
      ["候选上限", b[3]],
      ["步骤上限", b[4]],
    ]),
  );
}
document.querySelectorAll("[data-preset]").forEach((b) =>
  b.addEventListener("click", () => {
    preset = b.dataset.preset;
    document
      .querySelectorAll("[data-preset]")
      .forEach((x) => x.classList.toggle("selected", x === b));
    renderBudget();
  }),
);
$("scan-target").addEventListener("change", renderBudget);
let importVersion = 0;
$("artifact-file").addEventListener("change", async (event) => {
  const version = ++importVersion;
  const file = event.target.files[0];
  if (!file) return;
  $("import-results").hidden = true;
  $("import-list").replaceChildren();
  try {
    if (file.size > 10 * 1024 * 1024)
      throw new Error("文件超过 10MB，请使用较小的 findings.json");
    const data = JSON.parse(await file.text());
    if (version !== importVersion) return;
    const items = Array.isArray(data) ? data : data?.findings;
    if (!Array.isArray(items)) throw new Error("未找到 findings 数组");
    if (
      items.some(
        (item) => !item || typeof item !== "object" || Array.isArray(item),
      )
    )
      throw new Error("findings 中每一项必须是对象");
    $("import-status").textContent =
      `已在本地读取 ${file.name}，共 ${items.length} 个发现项。`;
    items.slice(0, 100).forEach((f, i) => {
      const block = node("section", "detail-section");
      block.style.margin = "0 24px 24px";
      append(
        block,
        node(
          "h3",
          "",
          `${i + 1}. ${typeof f.title === "string" ? f.title : typeof f.vuln_class === "string" ? f.vuln_class : "未命名发现"}`,
        ),
        node("pre", "", JSON.stringify(f, null, 2)),
      );
      $("import-list").append(block);
    });
    if (items.length > 100)
      $("import-list").append(
        node("p", "empty-state", "仅展示前 100 项，原文件未修改。"),
      );
    $("import-results").hidden = false;
  } catch (error) {
    if (version !== importVersion) return;
    $("import-list").replaceChildren();
    $("import-status").textContent = `导入失败：${error.message}`;
  }
});
renderRuns();
renderFindings();
renderBudget();
window.addEventListener("popstate", () =>
  setPage(location.hash.slice(1), false),
);
window.addEventListener("hashchange", () =>
  setPage(location.hash.slice(1), false),
);
setPage(location.hash.slice(1), false);
