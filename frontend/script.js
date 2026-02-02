const API_BASE = "";

const SEVERITY_COLORS = {
    critique: { bg: "#dc2626", color: "#fff" },
    "élevé": { bg: "#f59e0b", color: "#000" },
    moyen: { bg: "#3b82f6", color: "#fff" },
    faible: { bg: "#6b7280", color: "#fff" },
};

function getText() {
    return document.getElementById("text-input").value.trim();
}

function getFile() {
    const input = document.getElementById("file-input");
    return input.files.length > 0 ? input.files[0] : null;
}

function buildFormData() {
    const formData = new FormData();
    formData.append("text", getText());
    const file = getFile();
    if (file) {
        formData.append("file", file);
    }
    return formData;
}

function updateFileLabel() {
    const file = getFile();
    const label = document.getElementById("file-label-text");
    if (file) {
        label.textContent = file.name;
    } else {
        label.textContent = "+ Ajouter une piece jointe (PDF, Word, Excel)";
    }
}

function showResults() {
    document.getElementById("results").hidden = false;
}

function showRiskBanner(riskLevel, riskSummary) {
    const banner = document.getElementById("risk-banner");
    const icon = document.getElementById("risk-icon");
    const text = document.getElementById("risk-text");

    banner.hidden = false;
    banner.className = "risk-banner";

    if (riskLevel.includes("CRITIQUE")) {
        banner.classList.add("critique");
        icon.textContent = "STOP";
    } else if (riskLevel.includes("ELEVE")) {
        banner.classList.add("eleve");
        icon.textContent = "ALERTE";
    } else if (riskLevel.includes("MOYEN")) {
        banner.classList.add("moyen");
        icon.textContent = "ATTENTION";
    } else if (riskLevel === "aucun") {
        banner.classList.add("aucun");
        icon.textContent = "OK";
    } else {
        banner.classList.add("faible");
        icon.textContent = "INFO";
    }

    let displayText = " " + riskLevel;
    if (riskSummary) {
        displayText += " — " + riskSummary;
    }
    text.textContent = displayText;
}

function showAttachment(name, text) {
    const card = document.getElementById("attachment-card");
    if (name && text) {
        card.hidden = false;
        document.getElementById("attachment-name").textContent = name;
        document.getElementById("attachment-text").textContent = text;
    } else {
        card.hidden = true;
    }
}

function highlightText(text, entities) {
    const positioned = entities.filter(e => e.start >= 0).sort((a, b) => a.start - b.start);
    if (!positioned.length) return escapeHtml(text);

    let result = "";
    let lastEnd = 0;

    for (const ent of positioned) {
        result += escapeHtml(text.slice(lastEnd, ent.start));
        const severity = ent.severity || "faible";
        const title = ent.reason ? `${ent.label} (${severity}) — ${ent.reason}` : `${ent.label} (${severity})`;
        result += `<span class="pii-tag" data-severity="${severity}" title="${escapeAttr(title)}">${escapeHtml(ent.text)}</span>`;
        lastEnd = ent.end;
    }
    result += escapeHtml(text.slice(lastEnd));
    return result;
}

function renderEntitiesList(entities) {
    let html = "";
    for (const ent of entities) {
        const severity = ent.severity || "faible";
        const c = SEVERITY_COLORS[severity] || SEVERITY_COLORS.faible;
        const source = ent.source === "ai" ? " (IA)" : "";
        const reason = ent.reason ? ` — ${ent.reason}` : "";
        html += `<div class="entity-item">
            <span class="entity-severity" style="background:${c.bg};color:${c.color}">${severity.toUpperCase()}</span>
            <span class="entity-label">${ent.label}${source}</span>
            <span class="entity-text">"${escapeHtml(ent.text)}"</span>
            <span class="entity-reason">${escapeHtml(reason)}</span>
        </div>`;
    }
    return html;
}

function renderLegend(entities) {
    const seen = new Map();
    for (const e of entities) {
        if (!seen.has(e.label)) {
            seen.set(e.label, e.severity || "faible");
        }
    }
    let html = "";
    for (const [label, severity] of seen) {
        const c = SEVERITY_COLORS[severity] || SEVERITY_COLORS.faible;
        html += `<div class="legend-item"><span class="legend-dot" style="background:${c.bg}"></span>${label}</div>`;
    }
    return html;
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    return str.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function analyzeText() {
    const text = getText();
    const file = getFile();
    if (!text && !file) return;

    document.getElementById("btn-analyze").textContent = "Analyse en cours...";
    document.getElementById("btn-analyze").disabled = true;

    try {
        const res = await fetch(`${API_BASE}/analyze`, {
            method: "POST",
            body: buildFormData(),
        });
        const data = await res.json();

        showRiskBanner(data.risk_level, data.risk_summary);
        showAttachment(data.attachment_name, data.attachment_text);
        showResults();

        document.getElementById("pii-count").textContent = `${data.count} donnee(s) sensible(s) detectee(s)`;
        document.getElementById("highlighted-text").innerHTML = highlightText(text, data.entities);
        document.getElementById("pii-legend").innerHTML = renderLegend(data.entities);

        const detailEl = document.getElementById("entities-detail");
        if (detailEl) {
            detailEl.innerHTML = renderEntitiesList(data.entities);
            detailEl.hidden = false;
        }

        document.getElementById("anonymized-card").hidden = true;
    } finally {
        document.getElementById("btn-analyze").textContent = "Verifier la securite";
        document.getElementById("btn-analyze").disabled = false;
    }
}

async function anonymizeText() {
    const text = getText();
    const file = getFile();
    if (!text && !file) return;

    document.getElementById("btn-anonymize").textContent = "Masquage en cours...";
    document.getElementById("btn-anonymize").disabled = true;

    try {
        const res = await fetch(`${API_BASE}/anonymize`, {
            method: "POST",
            body: buildFormData(),
        });
        const data = await res.json();

        showRiskBanner(data.risk_level, data.risk_summary);
        showResults();

        document.getElementById("pii-count").textContent = `${data.entities.length} donnee(s) sensible(s) detectee(s)`;
        document.getElementById("highlighted-text").innerHTML = highlightText(text, data.entities);
        document.getElementById("pii-legend").innerHTML = renderLegend(data.entities);

        const detailEl = document.getElementById("entities-detail");
        if (detailEl) {
            detailEl.innerHTML = renderEntitiesList(data.entities);
            detailEl.hidden = false;
        }

        document.getElementById("anonymized-card").hidden = false;
        document.getElementById("anonymized-text").textContent = data.anonymized;
    } finally {
        document.getElementById("btn-anonymize").textContent = "Masquer les donnees";
        document.getElementById("btn-anonymize").disabled = false;
    }
}

async function downloadReport() {
    const text = getText();
    const file = getFile();
    if (!text && !file) return;

    document.getElementById("btn-report").textContent = "Generation...";
    document.getElementById("btn-report").disabled = true;

    try {
        const res = await fetch(`${API_BASE}/report`, {
            method: "POST",
            body: buildFormData(),
        });
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "rapport_securite.pdf";
        a.click();
        URL.revokeObjectURL(url);
    } finally {
        document.getElementById("btn-report").textContent = "Rapport PDF";
        document.getElementById("btn-report").disabled = false;
    }
}

function copyAnonymized() {
    const text = document.getElementById("anonymized-text").textContent;
    navigator.clipboard.writeText(text);
}
