document.addEventListener("DOMContentLoaded", () => {
    const fileInput = document.getElementById("file-input");
    const dropZone = document.getElementById("drop-zone");
    const fileNameLabel = document.getElementById("file-name-label");
    const btnAnalyze = document.getElementById("btn-analyze");
    const btnQuickSample = document.getElementById("btn-quick-sample");
    const spinner = document.getElementById("analyze-spinner");
    const alertBanner = document.getElementById("alert-banner");

    const metricsSection = document.getElementById("metrics-section");
    const resultsSection = document.getElementById("results-section");

    const metricTotalFlows = document.getElementById("metric-total-flows");
    const metricMlAttacks = document.getElementById("metric-ml-attacks");
    const metricMlRate = document.getElementById("metric-ml-rate");
    const metricRuleAttacks = document.getElementById("metric-rule-attacks");
    const metricAgreement = document.getElementById("metric-agreement");
    const metricLatency = document.getElementById("metric-latency");

    const attackBreakdownTags = document.getElementById("attack-breakdown-tags");
    const evidenceTableBody = document.getElementById("evidence-table-body");

    let currentFile = null;

    // Drag & drop listeners
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });

    function handleFileSelect(file) {
        if (!file.name.toLowerCase().endsWith('.csv')) {
            showAlert("Invalid file type. Please select a .csv file.", "error");
            return;
        }

        currentFile = file;
        const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
        fileNameLabel.textContent = `Selected: ${file.name} (${sizeMb} MB)`;
        btnAnalyze.disabled = false;
        hideAlert();
    }

    // Quick Sample button
    btnQuickSample.addEventListener('click', async () => {
        try {
            showAlert("Fetching traffic sample...", "success");
            const res = await fetch("/api/sample");
            if (!res.ok) throw new Error("Could not fetch sample");
            const blob = await res.blob();
            const sampleFile = new File([blob], "cicids2017_demo_sample.csv", { type: "text/csv" });
            handleFileSelect(sampleFile);
            triggerAnalysis();
        } catch (err) {
            showAlert("Failed to load sample: " + err.message, "error");
        }
    });

    btnAnalyze.addEventListener('click', triggerAnalysis);

    async function triggerAnalysis() {
        if (!currentFile) return;

        btnAnalyze.disabled = true;
        spinner.style.display = "inline-block";
        hideAlert();

        const formData = new FormData();
        formData.append("file", currentFile);

        try {
            const response = await fetch("/api/detect", {
                method: "POST",
                body: formData
            });

            // Resilient JSON parsing
            const contentType = response.headers.get("content-type") || "";
            let data;
            if (contentType.includes("application/json")) {
                data = await response.json();
            } else {
                const text = await response.text();
                const match = text.match(/<title>(.*?)<\/title>/i) || text.match(/<h1>(.*?)<\/h1>/i);
                const cleanError = match ? match[1] : (text.slice(0, 150) || "Server error");
                throw new Error(`Upload error (${response.status}): ${cleanError}`);
            }

            if (!response.ok) {
                throw new Error(data.error || "Analysis failed.");
            }

            renderDashboard(data);
            const extraNote = data.note ? data.note : "";
            showAlert(`✅ Analysis complete in ${data.latency_ms} ms.${extraNote}`, "success");
        } catch (err) {
            showAlert(err.message, "error");
        } finally {
            btnAnalyze.disabled = false;
            spinner.style.display = "none";
        }
    }

    function renderDashboard(data) {
        const s = data.summary;

        // Populate KPIs
        metricTotalFlows.textContent = s.total_records.toLocaleString();
        metricMlAttacks.textContent = s.ml_detected_attacks.toLocaleString();
        
        const attackPct = s.total_records > 0 ? ((s.ml_detected_attacks / s.total_records) * 100).toFixed(1) : 0;
        metricMlRate.textContent = `${attackPct}% of flows flagged as malicious`;

        metricRuleAttacks.textContent = s.rule_detected_attacks.toLocaleString();
        metricAgreement.textContent = `${s.engine_agreement_pct}%`;
        metricLatency.textContent = `Inference Latency: ${data.latency_ms} ms`;

        // Render attack breakdown tags
        attackBreakdownTags.innerHTML = "";
        for (const [attackType, count] of Object.entries(s.attack_type_breakdown)) {
            if (count > 0) {
                const tag = document.createElement("span");
                tag.className = "tag-pill";
                tag.textContent = `${attackType}: ${count}`;
                attackBreakdownTags.appendChild(tag);
            }
        }

        // Render Evidence Table
        evidenceTableBody.innerHTML = "";
        if (data.suspicious_records.length === 0) {
            evidenceTableBody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 2rem;">No suspicious flow records detected. All traffic evaluated as BENIGN.</td></tr>`;
        } else {
            data.suspicious_records.forEach(rec => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>#${rec.record_id}</td>
                    <td><span class="badge-severity severity-${rec.severity}">${rec.severity}</span></td>
                    <td>${rec.dest_port}</td>
                    <td>${Math.round(rec.flow_duration_us).toLocaleString()}</td>
                    <td>${rec.total_fwd_pkts}</td>
                    <td>${Math.round(rec.flow_bytes_per_sec).toLocaleString()}</td>
                    <td><span style="color:${rec.rule_verdict === 'ATTACK' ? '#ef4444' : '#10b981'}">${rec.rule_verdict}</span></td>
                    <td><span style="color:${rec.ml_verdict === 'ATTACK' ? '#ef4444' : '#10b981'}">${rec.ml_verdict}</span></td>
                    <td><strong>${rec.ml_confidence_pct}%</strong></td>
                `;
                evidenceTableBody.appendChild(tr);
            });
        }

        // Show Sections
        metricsSection.classList.remove("hidden");
        resultsSection.classList.remove("hidden");
    }

    function showAlert(msg, type) {
        alertBanner.textContent = msg;
        alertBanner.className = `alert-banner ${type}`;
        alertBanner.classList.remove("hidden");
    }

    function hideAlert() {
        alertBanner.classList.add("hidden");
    }
});
