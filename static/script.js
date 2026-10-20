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

    // Modal elements
    const attackModal = document.getElementById("attack-modal");
    const modalCloseBtn = document.getElementById("modal-close-btn");
    const modalDismissBtn = document.getElementById("modal-dismiss-btn");
    const modalSeverityBadge = document.getElementById("modal-severity-badge");
    const modalAttackTitle = document.getElementById("modal-attack-title");
    const modalRecordId = document.getElementById("modal-record-id");
    const modalExplanationSummary = document.getElementById("modal-explanation-summary");
    const modalReasonsList = document.getElementById("modal-reasons-list");
    const modalFeaturesGrid = document.getElementById("modal-features-grid");
    const modalMlVerdict = document.getElementById("modal-ml-verdict");
    const modalMlConfidence = document.getElementById("modal-ml-confidence");
    const modalRuleVerdict = document.getElementById("modal-rule-verdict");
    const modalRuleName = document.getElementById("modal-rule-name");

    function closeModal() {
        if (attackModal) attackModal.classList.add("hidden");
    }

    if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeModal);
    if (modalDismissBtn) modalDismissBtn.addEventListener("click", closeModal);
    if (attackModal) {
        attackModal.addEventListener("click", (e) => {
            if (e.target === attackModal) closeModal();
        });
    }

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && attackModal && !attackModal.classList.contains("hidden")) {
            closeModal();
        }
    });

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

        function openAttackModal(rec) {
            const exp = rec.explanation || {};
            const attackName = exp.attack_type || rec.attack_type || "Network Attack";

            modalSeverityBadge.className = `badge-severity severity-${rec.severity || 'CRITICAL'}`;
            modalSeverityBadge.textContent = rec.severity || "CRITICAL";
            modalAttackTitle.textContent = `${attackName} - Forensic Evidence`;
            modalRecordId.textContent = `Record #${rec.record_id}`;

            modalExplanationSummary.textContent = exp.summary || `Flow #${rec.record_id} was identified as ${attackName} by the detection engines with ${rec.ml_confidence_pct}% model confidence.`;

            // Populate Root Causes / Reasons List
            modalReasonsList.innerHTML = "";
            const reasons = exp.primary_reasons && exp.primary_reasons.length > 0 
                ? exp.primary_reasons 
                : [
                    `ML Model evaluated non-linear pattern indicating ${attackName} with ${rec.ml_confidence_pct}% confidence`,
                    `Traffic exhibited anomalous packet/flow timing on port ${rec.dest_port}`
                ];

            reasons.forEach(r => {
                const li = document.createElement("li");
                li.innerHTML = `<strong>Reason:</strong> ${r}`;
                modalReasonsList.appendChild(li);
            });

            // Populate Key Flow Metrics Comparison
            modalFeaturesGrid.innerHTML = "";
            const topFeatures = exp.top_features || [
                { name: "Destination Port", value: String(rec.dest_port), normal_range: "Standard service ports" },
                { name: "Flow Duration", value: `${Math.round(rec.flow_duration_us).toLocaleString()} µs`, normal_range: "> 1,000 µs normal" },
                { name: "Total Fwd Packets", value: String(rec.total_fwd_pkts), normal_range: "1 - 15 packets" },
                { name: "Flow Bytes/s", value: `${Math.round(rec.flow_bytes_per_sec).toLocaleString()} B/s`, normal_range: "< 100 KB/s normal" }
            ];

            topFeatures.forEach(feat => {
                const card = document.createElement("div");
                card.className = "metric-compare-card";
                card.innerHTML = `
                    <div class="metric-compare-name">${feat.name}</div>
                    <div class="metric-compare-val">${feat.value}</div>
                    <div class="metric-compare-baseline">Normal: ${feat.normal_range}</div>
                `;
                modalFeaturesGrid.appendChild(card);
            });

            // Dual-Engine consensus
            modalMlVerdict.textContent = rec.ml_verdict || "ATTACK";
            modalMlVerdict.style.color = (rec.ml_verdict === "ATTACK") ? "#ef4444" : "#10b981";
            modalMlConfidence.textContent = `Model Confidence: ${rec.ml_confidence_pct}%`;

            modalRuleVerdict.textContent = rec.rule_verdict || "ATTACK";
            modalRuleVerdict.style.color = (rec.rule_verdict === "ATTACK") ? "#ef4444" : "#10b981";
            modalRuleName.textContent = `Triggered: ${rec.rule_triggered || 'NO_RULE_TRIGGERED'}`;

            attackModal.classList.remove("hidden");
        }

        // Render Evidence Table
        evidenceTableBody.innerHTML = "";
        if (data.suspicious_records.length === 0) {
            evidenceTableBody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding: 2rem;">No suspicious flow records detected. All traffic evaluated as BENIGN.</td></tr>`;
        } else {
            data.suspicious_records.forEach(rec => {
                const tr = document.createElement("tr");
                tr.className = "clickable-row";
                const attackLabel = rec.attack_type || "Suspicious Attack";
                tr.innerHTML = `
                    <td>#${rec.record_id}</td>
                    <td><span class="badge-severity severity-${rec.severity}">${rec.severity}</span></td>
                    <td><strong style="color: var(--accent-cyan);">${attackLabel}</strong></td>
                    <td>${rec.dest_port}</td>
                    <td>${Math.round(rec.flow_duration_us).toLocaleString()}</td>
                    <td>${rec.total_fwd_pkts}</td>
                    <td>${Math.round(rec.flow_bytes_per_sec).toLocaleString()}</td>
                    <td><span style="color:${rec.rule_verdict === 'ATTACK' ? '#ef4444' : '#10b981'}">${rec.rule_verdict}</span></td>
                    <td><strong>${rec.ml_confidence_pct}%</strong></td>
                    <td><span class="view-details-link">Inspect Reasons 🔍</span></td>
                `;
                tr.addEventListener("click", () => {
                    openAttackModal(rec);
                });
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
