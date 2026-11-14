/* =========================================================
   Secure URL Shortener - Frontend JavaScript
   Connects to Flask Backend APIs:
   - POST /api/shorten
   - GET /api/links
========================================================= */

// DOM Elements
const shortenerForm = document.getElementById("shortener-form");
const longUrlInput = document.getElementById("long-url");
const shortenBtn = document.getElementById("shorten-btn");
const resultBox = document.getElementById("result-box");
const errorBox = document.getElementById("error-box");
const shortUrlText = document.getElementById("short-url-text");
const securityStatusBox = document.getElementById("security-status-box");
const copyBtn = document.getElementById("copy-btn");
const copyText = document.getElementById("copy-text");
const tableBody = document.getElementById("links-table-body");

// Fetch links list from backend on initial page load
async function fetchRecentLinks() {
  try {
    const response = await fetch("/api/links");
    const data = await response.json();

    if (data.success) {
      renderTable(data.links);
    }
  } catch (error) {
    console.error("Error fetching recent links:", error);
  }
}

// Render links into the HTML table
function renderTable(links) {
  tableBody.innerHTML = "";

  if (!links || links.length === 0) {
    const emptyRow = document.createElement("tr");
    emptyRow.innerHTML = `<td colspan="5" style="text-align: center; color: #666;">No links created yet.</td>`;
    tableBody.appendChild(emptyRow);
    return;
  }

  links.forEach((item) => {
    const row = document.createElement("tr");

    const statusClass = item.is_suspicious ? "warn" : "safe";
    const statusLabel = item.is_suspicious ? "⚠️ " + item.security_reason : "🛡️ " + item.security_reason;

    row.innerHTML = `
      <td>
        <span class="table-long-link" title="${item.original_url}">${item.original_url}</span>
      </td>
      <td>
        <a href="${item.short_url}" target="_blank" class="table-short-link" title="Open redirect" onclick="setTimeout(fetchRecentLinks, 800)">${item.short_url}</a>
      </td>
      <td>
        <span class="status-tag ${statusClass}">${statusLabel}</span>
      </td>
      <td><strong>${item.clicks}</strong></td>
      <td>
        <button class="table-copy-btn" onclick="copyTableLink('${item.short_url}', this)">
          Copy
        </button>
      </td>
    `;

    tableBody.appendChild(row);
  });
}

// Submit Form - Send POST request to Flask backend
shortenerForm.addEventListener("submit", async function (e) {
  e.preventDefault();

  const longUrl = longUrlInput.value.trim();
  if (!longUrl) return;

  // Clear previous error / state
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
  shortenBtn.disabled = true;
  shortenBtn.textContent = "Shortening...";

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
      // Show validation / backend error
      errorBox.textContent = result.error || "An error occurred while shortening URL.";
      errorBox.classList.remove("hidden");
      resultBox.classList.add("hidden");
    } else {
      // Success: Show the generated short link
      shortUrlText.textContent = result.short_url;
      copyText.textContent = "Copy";

      // Display security check status
      if (result.is_suspicious) {
        securityStatusBox.className = "security-status-badge security-warning";
        securityStatusBox.textContent = "⚠️ " + result.security_reason;
      } else {
        securityStatusBox.className = "security-status-badge security-safe";
        securityStatusBox.textContent = "🛡️ " + result.security_reason;
      }

      resultBox.classList.remove("hidden");
      longUrlInput.value = "";

      // Refresh table from server
      await fetchRecentLinks();
    }
  } catch (error) {
    errorBox.textContent = "Could not connect to the backend server. Is Flask running?";
    errorBox.classList.remove("hidden");
  } finally {
    shortenBtn.disabled = false;
    shortenBtn.textContent = "Shorten URL";
  }
});

// Copy button for main result box
copyBtn.addEventListener("click", function () {
  const url = shortUrlText.textContent;
  copyToClipboard(url, copyText);
});

// Copy button for individual table rows
window.copyTableLink = function (url, buttonElement) {
  navigator.clipboard.writeText(url).then(() => {
    const originalText = buttonElement.textContent;
    buttonElement.textContent = "Copied!";
    setTimeout(() => {
      buttonElement.textContent = originalText;
    }, 1500);
  }).catch(() => {
    fallbackCopyText(url);
    buttonElement.textContent = "Copied!";
    setTimeout(() => {
      buttonElement.textContent = "Copy";
    }, 1500);
  });
};

function copyToClipboard(text, textLabel) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showCopyDone(textLabel);
    }).catch(() => {
      fallbackCopyText(text);
      showCopyDone(textLabel);
    });
  } else {
    fallbackCopyText(text);
    showCopyDone(textLabel);
  }
}

function showCopyDone(labelElement) {
  if (labelElement) labelElement.textContent = "Copied!";
  setTimeout(() => {
    if (labelElement) labelElement.textContent = "Copy";
  }, 1500);
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

// Auto-refresh links when the tab gains focus
window.addEventListener("focus", fetchRecentLinks);

// Initial fetch when page loads
fetchRecentLinks();
