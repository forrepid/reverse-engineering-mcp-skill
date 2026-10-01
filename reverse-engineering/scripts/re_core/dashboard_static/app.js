const $ = (id) => document.getElementById(id);
const dateText = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(date);
};
const addCell = (row, value, className = "") => {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value == null ? "—" : String(value);
  row.append(cell);
  return cell;
};
const displayValues = (event) => {
  const values = event.values || {};
  const lines = [];
  for (const [key, label] of [["runtime_oep_va", "Runtime VA"], ["runtime_oep_rva", "Runtime RVA"], ["dump_file_offset", "Dump offset"], ["declared_ep_va", "Declared VA"], ["declared_ep_rva", "Declared RVA"], ["provider", "Provider"], ["network", "Network"], ["timeout_seconds", "Timeout s"], ["sample_sha256", "Sample SHA-256"]]) {
    if (values[key] !== undefined && values[key] !== null) {
      const isAddress = ["runtime_oep_va", "runtime_oep_rva", "dump_file_offset", "declared_ep_va", "declared_ep_rva"].includes(key);
      const value = typeof values[key] === "number" && isAddress ? `0x${Number(values[key]).toString(16).toUpperCase()}` : String(values[key]);
      lines.push(`${label}: ${value}`);
    }
  }
  if (values.display_text) lines.unshift(String(values.display_text));
  return lines.join("\n") || "Ek değer yok";
};
const renderOep = (event) => {
  if (!event) return;
  const values = event.values || {};
  $("oep-description").textContent = event.description || event.operation;
  $("oep-time").textContent = dateText(event.timestamp_utc);
  const chip = $("oep-status");
  const verified = event.operation === "oep_runtime_verify" && values.runtime_verified === true;
  chip.textContent = verified ? "DOĞRULANDI" : event.status === "rejected" ? "REDDEDİLDİ" : event.status === "inconclusive" ? "SONUÇSUZ" : "DOĞRULANMADI";
  chip.className = `status-chip ${verified ? "verified" : event.status === "rejected" ? "failed" : "neutral"}`;
  if (verified) {
    $("oep-value").textContent = `VA 0x${Number(values.runtime_oep_va).toString(16).toUpperCase()}`;
    $("oep-subvalue").textContent = `RVA 0x${Number(values.runtime_oep_rva).toString(16).toUpperCase()} · file offset 0x${Number(values.dump_file_offset).toString(16).toUpperCase()}`;
  } else {
    $("oep-value").textContent = "NOT VERIFIED";
    $("oep-subvalue").textContent = values.display_text || "Statik EP/OEP adayları çalışma zamanı kanıtı değildir.";
  }
};
const renderEvents = (events) => {
  const body = $("event-rows");
  body.replaceChildren();
  if (!events.length) {
    const row = body.insertRow();
    addCell(row, "Henüz OEP işlemi yok.", "empty").colSpan = 4;
    return;
  }
  for (const event of events) {
    const row = body.insertRow();
    const timeCell = addCell(row, dateText(event.timestamp_utc));
    timeCell.title = event.timestamp_utc || "";
    const description = document.createElement("td");
    description.textContent = `${event.operation}\n${event.description || ""}`;
    row.append(description);
    const statusCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `pill ${event.status || "unknown"}`;
    pill.textContent = String(event.status || "unknown").toUpperCase();
    statusCell.append(pill);
    row.append(statusCell);
    addCell(row, displayValues(event), "values");
  }
};
const renderCandidates = (candidates) => {
  const body = $("candidate-rows");
  body.replaceChildren();
  for (const item of candidates || []) {
    const row = body.insertRow();
    addCell(row, item.provider);
    addCell(row, item.base_url);
    addCell(row, item.port);
    addCell(row, item.reachable ? "Açık port · kimlik doğrulanmadı" : "Erişilemiyor");
  }
  if (!body.rows.length) {
    const row = body.insertRow();
    addCell(row, "Keşif sonucu yok", "empty").colSpan = 4;
  }
};
async function refresh() {
  try {
    const [summaryResponse, eventsResponse] = await Promise.all([fetch("/api/summary", { cache: "no-store" }), fetch("/api/events?limit=100", { cache: "no-store" })]);
    if (!summaryResponse.ok || !eventsResponse.ok) throw new Error("dashboard API yanıt vermedi");
    const summary = await summaryResponse.json();
    const { events } = await eventsResponse.json();
    const connection = $("connection");
    connection.className = "connection live";
    connection.textContent = "Canlı yerel görünüm";
    const latest = events.find((event) => ["oep_static_candidates", "oep_runtime_verify"].includes(event.operation));
    renderOep(latest);
    renderEvents(events);
    renderCandidates(summary.local_broker_candidates);
    $("broker-status").textContent = String(summary.broker.status || "bilinmiyor").replaceAll("_", " ").toUpperCase();
    $("broker-detail").textContent = `${summary.broker.provider || "provider yok"} · capture ${summary.broker.live_capture_ready ? "hazır" : "kapalı"}`;
    const activity = summary.latest_activity;
    $("last-operation").textContent = activity ? activity.operation : "—";
    $("last-operation-time").textContent = activity ? dateText(activity.timestamp_utc) : "Henüz kayıt yok";
    $("updated-at").textContent = `Güncellendi ${dateText(summary.server_time_utc)}`;
  } catch (error) {
    const connection = $("connection");
    connection.className = "connection offline";
    connection.textContent = "Gösterge API çevrimdışı";
  }
}
$("refresh").addEventListener("click", refresh);
refresh();
window.setInterval(refresh, 2500);
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
