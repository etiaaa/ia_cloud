const API_BASE = "";

const LABEL_COLORS = {
    NOM: { bg: "#fde68a", color: "#92400e" },
    EMAIL: { bg: "#bfdbfe", color: "#1e40af" },
    TELEPHONE: { bg: "#c7d2fe", color: "#3730a3" },
    ADRESSE: { bg: "#bbf7d0", color: "#166534" },
    ORGANISATION: { bg: "#e9d5ff", color: "#6b21a8" },
    SECU: { bg: "#fecaca", color: "#991b1b" },
    IBAN: { bg: "#fed7aa", color: "#9a3412" },
};

function getText() {
    return document.getElementById("text-input").value.trim();
}

function showResults() {
    document.getElementById("results").hidden = false;
}

function highlightText(text, entities) {
    if (!entities.length) return escapeHtml(text);

    let result = "";
    let lastEnd = 0;

    for (const ent of entities) {
        result += escapeHtml(text.slice(lastEnd, ent.start));
        result += `<span class="pii-tag" data-label="${ent.label}" title="${ent.label}">${escapeHtml(ent.text)}</span>`;
        lastEnd = ent.end;
    }
    result += escapeHtml(text.slice(lastEnd));
    return result;
}

function renderLegend(entities) {
    const labels = [...new Set(entities.map((e) => e.label))];
    return labels
        .map((label) => {
            const c = LABEL_COLORS[label] || { bg: "#e5e7eb", color: "#374151" };
            return `<div class="legend-item"><span class="legend-dot" style="background:${c.bg}"></span>${label}</div>`;
        })
        .join("");
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

async function analyzeText() {
    const text = getText();
    if (!text) return;

    const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
    });
    const data = await res.json();

    showResults();
    document.getElementById("pii-count").textContent = `${data.count} donnée(s) personnelle(s) détectée(s)`;
    document.getElementById("highlighted-text").innerHTML = highlightText(text, data.entities);
    document.getElementById("pii-legend").innerHTML = renderLegend(data.entities);
    document.getElementById("anonymized-card").hidden = true;
}

async function anonymizeText() {
    const text = getText();
    if (!text) return;

    const res = await fetch(`${API_BASE}/anonymize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
    });
    const data = await res.json();

    showResults();
    document.getElementById("pii-count").textContent = `${data.entities.length} donnée(s) personnelle(s) détectée(s)`;
    document.getElementById("highlighted-text").innerHTML = highlightText(text, data.entities);
    document.getElementById("pii-legend").innerHTML = renderLegend(data.entities);

    document.getElementById("anonymized-card").hidden = false;
    document.getElementById("anonymized-text").textContent = data.anonymized;
}

async function downloadReport() {
    const text = getText();
    if (!text) return;

    const res = await fetch(`${API_BASE}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "rapport_rgpd.pdf";
    a.click();
    URL.revokeObjectURL(url);
}

function copyAnonymized() {
    const text = document.getElementById("anonymized-text").textContent;
    navigator.clipboard.writeText(text);
}
