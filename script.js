"use strict";

const root = document.querySelector("#app");
const suspiciousKeywords = ["login", "verify", "secure", "account", "update", "banking", "password", "confirmation"];
const shorteningServices = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "shorturl.at"]);
const urlInput = document.querySelector("#url");
const charCount = document.querySelector("#char-count");
const errorBox = document.querySelector("#error");

const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[character]));
const check = (name, status, detail, points = 0) => ({ name, status, detail, points });
const isIpHost = (hostname) => /^\[[0-9a-f:]+\]$|^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);

function analyzeUrl(rawValue) {
    const cleaned = rawValue.trim();
    if (!cleaned) throw new Error("Please enter a URL to analyze.");
    if (cleaned.length > 2048) throw new Error("The URL is too long to analyze (maximum 2,048 characters).");
    if (!/^https?:\/\//i.test(cleaned)) throw new Error("Include a web scheme such as https:// or http://.");

    let parsed;
    try { parsed = new URL(cleaned); } catch (_error) { throw new Error("Enter a complete HTTP or HTTPS URL with a domain name."); }
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) throw new Error("Enter a complete HTTP or HTTPS URL with a domain name.");
    if (parsed.port && !/^\d+$/.test(parsed.port)) throw new Error("The URL contains an invalid port number.");

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const loweredUrl = cleaned.toLowerCase();
    const pathAndQuery = `${parsed.pathname}?${parsed.search.slice(1)}`.toLowerCase();
    const labels = hostname.split(".").filter(Boolean);
    const ipAddress = isIpHost(hostname);
    const subdomains = ipAddress ? 0 : Math.max(0, labels.length - 2);
    const keywordHits = suspiciousKeywords.filter((keyword) => loweredUrl.includes(keyword)).sort();
    const hyphenCount = (loweredUrl.match(/-/g) || []).length;
    const digitCount = (hostname.match(/\d/g) || []).length;
    const hasCredentials = Boolean(parsed.username || parsed.password) || cleaned.includes("@");
    const unusualStructure = !hostname || (parsed.port && !["80", "443"].includes(parsed.port)) || Boolean(parsed.username || parsed.password) || parsed.pathname.includes("//") || parsed.pathname.includes("\\");

    const checks = [
        check("HTTPS encryption", parsed.protocol === "https:" ? "pass" : "warning", parsed.protocol === "https:" ? "HTTPS is used for the connection." : "HTTP does not encrypt the connection in transit.", parsed.protocol === "https:" ? 0 : 15),
        check("IP address host", ipAddress ? "warning" : "pass", ipAddress ? "The host is a numeric IP address rather than a named domain." : "The host uses a named domain.", ipAddress ? 25 : 0),
        check("URL length", cleaned.length > 120 ? "warning" : "pass", `The URL contains ${cleaned.length} characters.${cleaned.length > 120 ? " Long URLs can hide important details." : ""}`, cleaned.length > 120 ? 10 : 0),
        check("Subdomain count", subdomains >= 3 ? "warning" : "pass", `The hostname contains ${subdomains} subdomain(s).${subdomains >= 3 ? " Multiple subdomains can make the real domain harder to spot." : ""}`, subdomains >= 3 ? 10 : 0),
        check("At-symbol or embedded credentials", hasCredentials ? "warning" : "pass", hasCredentials ? "An @ symbol or embedded user information can obscure the actual destination." : "No @ symbol or embedded credentials were found.", hasCredentials ? 20 : 0),
        check("Hyphen usage", hyphenCount >= 3 ? "warning" : "pass", `The URL contains ${hyphenCount} hyphen(s).${hyphenCount >= 3 ? " Many hyphens may indicate a look-alike domain." : ""}`, hyphenCount >= 3 ? 10 : 0),
        check("Numeric host characters", digitCount >= 4 ? "warning" : "pass", `The hostname contains ${digitCount} number(s).${digitCount >= 4 ? " Unusual number patterns deserve extra review." : ""}`, digitCount >= 4 ? 5 : 0),
        check("Suspicious keywords", keywordHits.length ? "warning" : "pass", keywordHits.length ? `Found: ${keywordHits.join(", ")}` : "No common urgency or credential-related keywords were found.", Math.min(15, keywordHits.length * 5)),
        check("URL structure", unusualStructure ? "warning" : "pass", unusualStructure ? "The URL contains an unusual port, credentials, or path separators." : "The URL structure is conventional.", unusualStructure ? 10 : 0),
        check("Known URL shortener", shorteningServices.has(hostname) ? "warning" : "pass", shorteningServices.has(hostname) ? "A shortening service hides the final destination until the link is opened." : "The host is not a commonly recognized URL shortener.", shorteningServices.has(hostname) ? 10 : 0)
    ];

    const score = Math.min(100, checks.reduce((total, item) => total + item.points, 0));
    const classification = score <= 30 ? "Likely Safe" : score <= 60 ? "Suspicious" : "Potential Phishing";
    const tone = score <= 30 ? "safe" : score <= 60 ? "suspicious" : "danger";
    const reasons = [];
    if (parsed.protocol !== "https:") reasons.push("HTTP is used");
    if (ipAddress) reasons.push("the host is an IP address");
    if (keywordHits.length) reasons.push("credential or urgency-related words appear");
    if (!reasons.length) reasons.push("the inspected URL structure contains few warning signals");
    return { url: cleaned, score, classification, tone, checks, subdomains, pathPreview: pathAndQuery.slice(0, 120), summary: `${classification} based on a transparent score of ${score}/100: ${reasons.join("; ")}.` };
}

function renderResult(report) {
    const checks = report.checks.map((item) => `<article class="check-card status-${item.status}"><div class="check-card-top"><span class="check-icon">${item.status === "pass" ? "&#10003;" : "!"}</span><span class="check-status">${item.status}</span></div><h3>${escapeHtml(item.name)}</h3><p>${escapeHtml(item.detail)}</p><span class="points${item.points ? "" : " neutral"}">${item.points ? `+${item.points} risk points` : "No points added"}</span></article>`).join("");
    root.innerHTML = `<main class="site-shell result-shell"><nav class="topbar" aria-label="Main navigation"><a class="brand" href="#" id="brand-link"><span class="brand-mark">></span> PHISHING URL DETECTOR</a><a class="text-link" href="#" id="new-scan">&#8592; New scan</a></nav><section class="result-header reveal"><div><p class="eyebrow">SCAN COMPLETE / URL RISK ASSESSMENT</p><h1>Read the signals.</h1></div><p class="result-disclaimer">This is an educational assessment based on URL characteristics. It is not proof that a website is safe or malicious.</p></section><section class="score-layout reveal delay-1"><div class="score-card tone-${report.tone}"><div class="score-card-top"><span>RISK SCORE</span><span>0 — 100</span></div><div class="score-value">${report.score}<small>/100</small></div><div class="meter" role="meter" aria-label="Risk score" aria-valuenow="${report.score}" aria-valuemin="0" aria-valuemax="100"><span style="width:${report.score}%"></span></div><div class="classification"><span class="classification-dot"></span><strong>${report.classification}</strong></div><p>${escapeHtml(report.summary)}</p></div><div class="url-card"><p class="eyebrow">SUBMITTED URL</p><code>${escapeHtml(report.url)}</code><div class="url-facts"><span>SUBDOMAINS <strong>${report.subdomains}</strong></span><span>PATH PREVIEW <strong>${escapeHtml(report.pathPreview || "/")}</strong></span></div></div></section><section class="checks-section reveal delay-2"><div class="section-heading"><div><p class="eyebrow">TRANSPARENT BREAKDOWN</p><h2>What was checked</h2></div><span class="check-legend"><i class="legend-pass"></i> PASS <i class="legend-warning"></i> WARNING</span></div><div class="checks-grid">${checks}</div></section><section class="score-guide reveal delay-3"><div><p class="eyebrow">SCORING GUIDE</p><h2>How to read the score</h2></div><div class="guide-items"><div><strong>0—30</strong><span class="guide-safe">Likely Safe</span><p>Few URL-based warning signals were found.</p></div><div><strong>31—60</strong><span class="guide-suspicious">Suspicious</span><p>Review the warnings before trusting the link.</p></div><div><strong>61—100</strong><span class="guide-danger">Potential Phishing</span><p>Several indicators deserve strong caution.</p></div></div></section><div class="bottom-callout"><strong>Remember:</strong> HTTPS only encrypts a connection. It does not prove that the website owner is trustworthy.</div><footer><span>PHISHING URL DETECTOR / STUDENT CYBERSECURITY PROJECT</span><span><a href="#" id="footer-new-scan">RUN ANOTHER SCAN &#8594;</a></span></footer></main>`;
    ["brand-link", "new-scan", "footer-new-scan"].forEach((id) => document.querySelector(`#${id}`).addEventListener("click", (event) => { event.preventDefault(); window.location.reload(); }));
}

function showError(message) { errorBox.textContent = message; errorBox.hidden = false; }
function updateCount() { charCount.textContent = `${urlInput.value.length} / 2048`; }

urlInput.addEventListener("input", () => { errorBox.hidden = true; updateCount(); });
document.querySelector("#url-form").addEventListener("submit", (event) => { event.preventDefault(); try { renderResult(analyzeUrl(urlInput.value)); } catch (error) { showError(error.message); } });
document.querySelectorAll("[data-example]").forEach((button) => button.addEventListener("click", () => { urlInput.value = button.dataset.example; updateCount(); errorBox.hidden = true; urlInput.focus(); }));
updateCount();
