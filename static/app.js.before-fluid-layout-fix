const state = {
    currentJob: null,
    pollTimer: null,
};

const elements = {
    scoreValue: document.getElementById("scoreValue"),
    scoreRating: document.getElementById("scoreRating"),
    scoreTakeaway: document.getElementById("scoreTakeaway"),
    openServices: document.getElementById("openServices"),
    devicesFound: document.getElementById("devicesFound"),
    missingHeaders: document.getElementById("missingHeaders"),
    totalScans: document.getElementById("totalScans"),
    jobTitle: document.getElementById("jobTitle"),
    jobSubtitle: document.getElementById("jobSubtitle"),
    resultsArea: document.getElementById("resultsArea"),
    loader: document.getElementById("loader"),
};

async function api(path, options = {}) {
    const response = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...options,
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}

function setLoading(isLoading) {
    elements.loader.classList.toggle("hidden", !isLoading);
}

function priorityClass(priority) {
    if (priority === "high" || priority === "critical") return "risk-high";
    if (priority === "medium" || priority === "watch") return "risk-medium";
    return "risk-low";
}

async function refreshSummary() {
    const summary = await api("/api/summary");

    elements.scoreValue.textContent = summary.exposure_score ?? "--";
    elements.scoreRating.textContent = summary.rating || "waiting";
    elements.scoreRating.className = `score-rating ${priorityClass(summary.rating)}`;
    elements.scoreTakeaway.textContent = summary.executive_takeaway || "Run a scan to generate a summary.";

    const findings = summary.latest_findings || {};
    elements.openServices.textContent = findings.open_services || 0;
    elements.devicesFound.textContent = findings.devices || 0;
    elements.missingHeaders.textContent = findings.missing_headers || 0;
    elements.totalScans.textContent = summary.total_scans || 0;
}

async function startJob(path, payload) {
    clearInterval(state.pollTimer);
    setLoading(true);

    elements.jobTitle.textContent = "Queued assessment job";
    elements.jobSubtitle.textContent = "SentinelScope is starting the background scan.";
    elements.resultsArea.innerHTML = "";

    try {
        const job = await api(path, {
            method: "POST",
            body: JSON.stringify(payload),
        });

        state.currentJob = job.job_id;
        pollJob(job.job_id);
        state.pollTimer = setInterval(() => pollJob(job.job_id), 1200);
    } catch (error) {
        setLoading(false);
        renderError(error.message);
    }
}

async function pollJob(jobId) {
    try {
        const job = await api(`/api/jobs/${jobId}`);
        elements.jobTitle.textContent = `${formatTitle(job.type)}: ${job.status}`;
        elements.jobSubtitle.textContent = `Job ID ${job.job_id} • Started ${new Date(job.created_at).toLocaleString()}`;

        if (job.status === "completed") {
            clearInterval(state.pollTimer);
            setLoading(false);
            renderResults(job.result);
            refreshSummary();
        }

        if (job.status === "failed") {
            clearInterval(state.pollTimer);
            setLoading(false);
            renderError(job.error);
        }
    } catch (error) {
        clearInterval(state.pollTimer);
        setLoading(false);
        renderError(error.message);
    }
}

function formatTitle(value) {
    return String(value || "")
        .replaceAll("_", " ")
        .replace(/\b\w/g, char => char.toUpperCase());
}

function renderError(message) {
    elements.resultsArea.innerHTML = `
        <div class="error-box">
            <h3>Assessment blocked</h3>
            <p>${escapeHtml(message)}</p>
            <small>Safe mode allows localhost, private network targets, and approved internal reviews only.</small>
        </div>
    `;
}

function renderResults(result) {
    if (!result) {
        renderError("No result returned.");
        return;
    }

    if (result.scan_type === "port_scan") {
        renderPortScan(result);
        return;
    }

    if (result.scan_type === "web_security_header_scan") {
        renderHeaderScan(result);
        return;
    }

    if (result.scan_type === "private_subnet_device_discovery" || result.scan_type === "current_wifi_lan_discovery") {
        renderDiscovery(result);
        return;
    }

    elements.resultsArea.innerHTML = `<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`;
}

function renderPortScan(result) {
    const rows = result.open_ports.length
        ? result.open_ports.map(port => `
            <tr>
                <td>${port.port}</td>
                <td>${escapeHtml(port.service)}</td>
                <td><span class="pill ${priorityClass(port.risk)}">${port.risk}</span></td>
                <td>${port.state}</td>
            </tr>
        `).join("")
        : `<tr><td colspan="4">No open ports found in the selected review set.</td></tr>`;

    elements.resultsArea.innerHTML = `
        <div class="result-summary">
            <h3>Port scan complete</h3>
            <p>${escapeHtml(result.target)} resolved to ${escapeHtml(result.resolved_ip)}. ${result.open_port_count} open services found from ${result.ports_scanned} checked ports.</p>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>State</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>

        ${renderRecommendations(result.recommendations)}
    `;
}

function renderHeaderScan(result) {
    const missingRows = result.missing_headers.length
        ? result.missing_headers.map(item => `
            <tr>
                <td>${escapeHtml(item.header)}</td>
                <td><span class="pill ${priorityClass(item.risk)}">${item.risk}</span></td>
                <td>${escapeHtml(item.purpose)}</td>
            </tr>
        `).join("")
        : `<tr><td colspan="3">No missing headers found in this review.</td></tr>`;

    elements.resultsArea.innerHTML = `
        <div class="result-summary">
            <h3>Header scan complete</h3>
            <p>${escapeHtml(result.url)} returned status ${result.status_code}. ${result.missing_count} security headers are missing.</p>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Missing Header</th>
                        <th>Risk</th>
                        <th>Why It Matters</th>
                    </tr>
                </thead>
                <tbody>${missingRows}</tbody>
            </table>
        </div>

        ${renderRecommendations(result.recommendations)}
    `;
}

function renderDiscovery(result) {
    const isCurrentLan = result.scan_type === "current_wifi_lan_discovery";

    if (isCurrentLan) {
        renderCurrentLanDiscovery(result);
        return;
    }

    const rows = result.devices.length
        ? result.devices.map(device => `
            <tr>
                <td>${escapeHtml(device.host)}</td>
                <td>${device.open_port_count}</td>
                <td><span class="pill ${priorityClass(device.highest_risk)}">${device.highest_risk}</span></td>
                <td>${(device.open_ports || []).map(port => `${port.port}`).join(", ") || "None visible"}</td>
            </tr>
        `).join("")
        : `<tr><td colspan="4">No devices found with the selected service set.</td></tr>`;

    elements.resultsArea.innerHTML = `
        <div class="result-summary">
            <h3>Private discovery complete</h3>
            <p>${escapeHtml(result.cidr)} reviewed ${result.hosts_reviewed} private hosts. ${result.devices_found} devices showed open services.</p>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Open Services</th>
                        <th>Highest Risk</th>
                        <th>Ports</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>

        ${renderRecommendations(result.recommendations)}
    `;
}

function renderCurrentLanDiscovery(result) {
    const devices = result.devices || [];
    const visibleCount = result.visible_device_count || result.devices_found || 0;

    const inventoryCards = devices.length
        ? devices.map(device => `
            <article class="inventory-card">
                <div class="inventory-card-header">
                    <div>
                        <span class="label">IP Address</span>
                        <strong>${escapeHtml(device.host)}</strong>
                        ${device.is_teacher_machine ? `<small class="teacher-tag">Teacher machine</small>` : ""}
                    </div>
                    <span class="pill ${priorityClass(device.highest_risk)}">${escapeHtml(device.highest_risk || "low")}</span>
                </div>

                <div class="fluid-detail-grid">
                    <div>
                        <span>Name</span>
                        <strong>${escapeHtml(device.hostname || "Unknown")}</strong>
                    </div>
                    <div>
                        <span>Device Guess</span>
                        <strong>${escapeHtml(device.device_type_guess || "Unknown device")}</strong>
                    </div>
                    <div>
                        <span>Vendor Guess</span>
                        <strong>${escapeHtml(device.vendor_guess || "Unknown")}</strong>
                    </div>
                    <div>
                        <span>Detected By</span>
                        <strong>${escapeHtml(device.detection_note || "Visible")}</strong>
                    </div>
                    <div>
                        <span>Open Services</span>
                        <strong>${device.open_port_count || 0}</strong>
                    </div>
                    <div>
                        <span>Ports</span>
                        <strong>${(device.open_ports || []).map(port => `${port.port}`).join(", ") || "None visible"}</strong>
                    </div>
                    <div>
                        <span>Ping</span>
                        <strong>${device.responded_to_ping ? "Yes" : "No"}</strong>
                    </div>
                    <div>
                        <span>MAC</span>
                        <strong>${escapeHtml(device.mac_address || "Unknown")}</strong>
                    </div>
                </div>
            </article>
        `).join("")
        : `<div class="empty-state"><span>📡</span><p>No visible devices found.</p></div>`;

    elements.resultsArea.innerHTML = `
        <div class="result-summary lan-summary">
            <div>
                <h3>Current Wi-Fi / LAN discovery complete</h3>
                <p>
                    ${escapeHtml(result.cidr)} reviewed ${result.hosts_reviewed} possible private addresses.
                    SentinelScope found <strong>${visibleCount}</strong> visible devices.
                    Local teacher IP: <strong>${escapeHtml(result.local_ip)}</strong>.
                </p>
                <p><small>${escapeHtml(result.classroom_note || "")}</small></p>
            </div>

            <div class="lan-count-card">
                <span>Visible Devices Found</span>
                <strong>${visibleCount}</strong>
            </div>
        </div>

        <div class="inventory-section">
            <h3>Device Inventory</h3>
            <p>Responsive address, name, type, vendor, and detection list for visible devices on the current network.</p>
            <div class="inventory-card-list">
                ${inventoryCards}
            </div>
        </div>

        ${renderRecommendations(result.recommendations)}
    `;
}

function renderRecommendations(recommendations = []) {
    if (!recommendations.length) return "";

    return `
        <div class="recommendations">
            <h3>Remediation Queue</h3>
            ${recommendations.map(item => `
                <article>
                    <span class="pill ${priorityClass(item.priority)}">${escapeHtml(item.priority)}</span>
                    <div>
                        <strong>${escapeHtml(item.title)}</strong>
                        <p>${escapeHtml(item.guidance)}</p>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

async function loadClassroomLink() {
    const linkInput = document.getElementById("studentLink");
    if (!linkInput) return;

    try {
        const data = await api("/api/classroom/link");
        linkInput.value = data.student_url;
    } catch (error) {
        linkInput.value = "Could not detect classroom link. Restart app or check firewall.";
    }
}

async function refreshClassroomParticipants() {
    const box = document.getElementById("classroomParticipants");
    if (!box) return;

    try {
        const data = await api("/api/classroom/participants");
        const participants = data.participants || [];

        if (!participants.length) {
            box.innerHTML = "<small>No students joined yet.</small>";
            return;
        }

        box.innerHTML = participants.slice(0, 6).map(item => `
            <div class="mini-row">
                <strong>${escapeHtml(item.name)}</strong>
                <span>${escapeHtml(item.device_type)} • ${item.has_screen_lock ? "Screen lock confirmed" : "Screen lock not confirmed"}</span>
            </div>
        `).join("");
    } catch (error) {
        box.innerHTML = "<small>Classroom list unavailable.</small>";
    }
}

document.getElementById("scanLocalhostBtn")?.addEventListener("click", () => {
    startJob("/api/scan/localhost", { preset: "common" });
});

document.getElementById("targetScanForm")?.addEventListener("submit", event => {
    event.preventDefault();
    startJob("/api/scan/target", {
        target: document.getElementById("targetInput").value,
        preset: document.getElementById("targetPreset").value,
    });
});

document.getElementById("headerScanForm")?.addEventListener("submit", event => {
    event.preventDefault();
    startJob("/api/scan/headers", {
        url: document.getElementById("urlInput").value,
    });
});

document.getElementById("discoveryForm")?.addEventListener("submit", event => {
    event.preventDefault();
    startJob("/api/scan/discovery", {
        cidr: document.getElementById("cidrInput").value,
        preset: document.getElementById("discoveryPreset").value,
    });
});

document.getElementById("currentLanScanBtn")?.addEventListener("click", () => {
    startJob("/api/scan/current-lan", { include_ping: true });
});

document.getElementById("copyStudentLinkBtn")?.addEventListener("click", async () => {
    const linkInput = document.getElementById("studentLink");
    const button = document.getElementById("copyStudentLinkBtn");
    if (!linkInput || !button) return;

    await navigator.clipboard.writeText(linkInput.value);
    button.textContent = "Copied";
    setTimeout(() => {
        button.textContent = "Copy Student Link";
    }, 1400);
});

document.getElementById("refreshSummaryBtn")?.addEventListener("click", refreshSummary);

refreshSummary().catch(() => {});
loadClassroomLink();
refreshClassroomParticipants();
setInterval(refreshClassroomParticipants, 3000);
