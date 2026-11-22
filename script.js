/* =========================================================
   CypherLink - Frontend Logic & Inspection Breakdown
   ========================================================= */

// DOM Elements
const shortenerForm = document.getElementById("shortener-form");
const longUrlInput = document.getElementById("long-url");
const shortenBtn = document.getElementById("shorten-btn");
const resultBox = document.getElementById("result-box");
const errorBox = document.getElementById("error-box");
const shortUrlText = document.getElementById("short-url-text");
const resultStatusBadge = document.getElementById("result-status-badge");
const securityReasonText = document.getElementById("security-reason-text");
const secSummaryIcon = document.getElementById("sec-summary-icon");
const auditList = document.getElementById("audit-list");
const copyBtn = document.getElementById("copy-btn");
const copyText = document.getElementById("copy-text");
const copyIcon = document.getElementById("copy-icon");
const tableBody = document.getElementById("links-table-body");
const linksCountBadge = document.getElementById("links-count");

// Modal Elements
const inspectModal = document.getElementById("inspect-modal");
const modalIcon = document.getElementById("modal-icon");
const modalTitle = document.getElementById("modal-title");
const modalUrl = document.getElementById("modal-url");
const modalSummary = document.getElementById("modal-summary");
const modalChecksList = document.getElementById("modal-checks-list");

// Store fetched links for modal lookup
let currentLinksCache = [];

// Helper to escape HTML to prevent XSS in dynamic inserts
function escapeHTML(str) {
  if (!str) return "";
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

// Fetch links list from backend
async function fetchRecentLinks() {
  try {
    const response = await fetch("/api/links");
    const data = await response.json();

    if (data.success) {
      currentLinksCache = data.links || [];
      renderTable(currentLinksCache);
    }
  } catch (error) {
    console.error("Error fetching recent links:", error);
  }
}

// Render links into the HTML table
function renderTable(links) {
  tableBody.innerHTML = "";
  if (linksCountBadge) {
    linksCountBadge.textContent = `${links ? links.length : 0} ${links && links.length === 1 ? 'link' : 'links'}`;
  }

  if (!links || links.length === 0) {
    const emptyRow = document.createElement("tr");
    emptyRow.innerHTML = `<td colspan="6" style="text-align: center; color: var(--text-dim); padding: 30px;">No links shortened yet. Shorten your first link above!</td>`;
    tableBody.appendChild(emptyRow);
    return;
  }

  links.forEach((item, index) => {
    const row = document.createElement("tr");

    const statusBadge = item.is_suspicious 
      ? `<span class="badge badge-warn">⚠️ Suspicious</span>` 
      : `<span class="badge badge-safe">🛡️ Safe</span>`;

    const infoButton = (item.security_checks && item.security_checks.length > 0) || item.security_reason
      ? `<button class="btn-inspect" onclick="openInspectModal(${index})" title="${escapeHTML(item.security_reason)}">Details ⓘ</button>`
      : '';

    row.innerHTML = `
      <td>
        <span class="table-long-link" title="${escapeHTML(item.original_url)}">${escapeHTML(item.original_url)}</span>
      </td>
      <td>
        <a href="${escapeHTML(item.short_url)}" target="_blank" class="table-short-link" title="Open redirect" onclick="setTimeout(fetchRecentLinks, 800)">
          ${escapeHTML(item.short_url)}
        </a>
      </td>
      <td>
        <div class="status-cell-wrap">
          ${statusBadge}
          ${infoButton}
        </div>
      </td>
      <td>
        <span class="click-counter">${item.clicks}</span>
      </td>
      <td>
        <button class="btn-table-copy" onclick="copyTableLink('${escapeHTML(item.short_url)}', this)">
          Copy
        </button>
      </td>
    `;

    tableBody.appendChild(row);
  });
}

// Render dynamic audit list inside the result diagnostics card
function renderAuditList(checks, container) {
  container.innerHTML = "";
  if (!checks || checks.length === 0) return;

  checks.forEach(check => {
    const item = document.createElement("div");
    item.className = `audit-item ${check.passed ? 'passed' : 'failed'}`;
    const icon = check.passed ? '✓' : '⚠️';

    item.innerHTML = `
      <span class="audit-status-icon">${icon}</span>
      <div class="audit-text">
        <span class="audit-name">${escapeHTML(check.name)}:</span>
        <span class="audit-detail">${escapeHTML(check.detail)}</span>
      </div>
    `;
    container.appendChild(item);
  });
}

// Submit Form - Send POST request to Flask backend
shortenerForm.addEventListener("submit", async function (e) {
  e.preventDefault();

  let longUrl = longUrlInput.value.trim();
  if (!longUrl) return;

  // Auto-prepend https:// if the user typed a domain without protocol (e.g., mp3raid.com)
  if (!/^https?:\/\//i.test(longUrl)) {
    longUrl = "https://" + longUrl;
  }

  // Clear previous error / state
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
  shortenBtn.disabled = true;
  shortenBtn.innerHTML = `<span>Analyzing...</span>`;

  try {
    const response = await fetch("/api/shorten", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: longUrl })
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      errorBox.textContent = result.error || "An error occurred while shortening the URL.";
      errorBox.classList.remove("hidden");
      resultBox.classList.add("hidden");
    } else {
      // Show result
      shortUrlText.textContent = result.short_url;
      copyText.textContent = "Copy Link";
      copyIcon.textContent = "📋";

      // Badge status
      if (result.is_suspicious) {
        resultStatusBadge.className = "badge badge-warn";
        resultStatusBadge.innerHTML = "⚠️ Suspicious";
        if (secSummaryIcon) secSummaryIcon.textContent = "⚠️";
      } else {
        resultStatusBadge.className = "badge badge-safe";
        resultStatusBadge.innerHTML = "🛡️ Safe";
        if (secSummaryIcon) secSummaryIcon.textContent = "🛡️";
      }

      // Security Reason
      securityReasonText.textContent = result.security_reason;

      // Render diagnostic checks
      renderAuditList(result.security_checks || [], auditList);

      resultBox.classList.remove("hidden");
      longUrlInput.value = "";

      // Refresh table from server
      await fetchRecentLinks();
    }
  } catch (error) {
    errorBox.textContent = "Could not connect to the backend server. Please verify Flask is running.";
    errorBox.classList.remove("hidden");
  } finally {
    shortenBtn.disabled = false;
    shortenBtn.innerHTML = `<span>Shorten Link</span><span class="btn-arrow">→</span>`;
  }
});

// Copy button for main result box
copyBtn.addEventListener("click", function () {
  const url = shortUrlText.textContent;
  copyToClipboard(url, copyText, copyIcon);
});

// Copy button for individual table rows
window.copyTableLink = function (url, buttonElement) {
  navigator.clipboard.writeText(url).then(() => {
    const originalText = buttonElement.textContent;
    buttonElement.textContent = "Copied!";
    buttonElement.style.color = "#34d399";
    setTimeout(() => {
      buttonElement.textContent = originalText;
      buttonElement.style.color = "";
    }, 1500);
  }).catch(() => {
    fallbackCopyText(url);
    buttonElement.textContent = "Copied!";
    setTimeout(() => {
      buttonElement.textContent = "Copy";
    }, 1500);
  });
};

function copyToClipboard(text, textLabel, iconLabel) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showCopyDone(textLabel, iconLabel);
    }).catch(() => {
      fallbackCopyText(text);
      showCopyDone(textLabel, iconLabel);
    });
  } else {
    fallbackCopyText(text);
    showCopyDone(textLabel, iconLabel);
  }
}

function showCopyDone(textLabel, iconLabel) {
  if (textLabel) textLabel.textContent = "Copied!";
  if (iconLabel) iconLabel.textContent = "✓";
  setTimeout(() => {
    if (textLabel) textLabel.textContent = "Copy Link";
    if (iconLabel) iconLabel.textContent = "📋";
  }, 1600);
}

function fallbackCopyText(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.top = "-9999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand("copy");
  } catch (err) {
    console.error("Copy failed", err);
  }
  document.body.removeChild(textArea);
}

// Modal inspection functionality
window.openInspectModal = function(index) {
  const item = currentLinksCache[index];
  if (!item) return;

  modalIcon.textContent = item.is_suspicious ? "⚠️" : "🛡️";
  modalTitle.textContent = item.is_suspicious ? "Suspicious Link Reason & Audit" : "Safe Link Verification Audit";
  modalUrl.textContent = item.original_url;

  modalSummary.className = `modal-summary ${item.is_suspicious ? 'badge-warn' : 'badge-safe'}`;
  modalSummary.innerHTML = `<strong>Why is it ${item.is_suspicious ? 'Suspicious' : 'Safe'}?</strong><br>${escapeHTML(item.security_reason)}`;

  renderAuditList(item.security_checks || [], modalChecksList);

  inspectModal.classList.remove("hidden");
};

window.closeInspectModal = function() {
  inspectModal.classList.add("hidden");
};

// Auto-refresh links when the window gains focus
window.addEventListener("focus", fetchRecentLinks);

// Close modal on Escape key
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !inspectModal.classList.contains("hidden")) {
    closeInspectModal();
  }
});

// Toggle audit details
window.toggleAuditDetails = function() {
  const auditListEl = document.getElementById("audit-list");
  const toggleText = document.getElementById("audit-toggle-text");
  const toggleIcon = document.getElementById("audit-toggle-icon");
  if (!auditListEl) return;

  const isHidden = auditListEl.classList.contains("hidden");
  if (isHidden) {
    auditListEl.classList.remove("hidden");
    if (toggleText) toggleText.textContent = "Hide Details";
    if (toggleIcon) toggleIcon.textContent = "▲";
  } else {
    auditListEl.classList.add("hidden");
    if (toggleText) toggleText.textContent = "Show Details";
    if (toggleIcon) toggleIcon.textContent = "▼";
  }
};

// Initial fetch when page loads
fetchRecentLinks();
