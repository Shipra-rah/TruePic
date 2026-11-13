/**
 * TruePic — Image Authenticity & Forensics Assistant
 * Client-side Controller, Table Renderer & Forensic Report Generator
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM References
  const imageInput = document.getElementById('imageInput');
  const dropzone = document.getElementById('dropzone');
  const dropzonePrompt = document.getElementById('dropzonePrompt');
  const filePreview = document.getElementById('filePreview');
  const previewImg = document.getElementById('previewImg');
  const previewFilename = document.getElementById('previewFilename');
  const previewFilesize = document.getElementById('previewFilesize');
  const btnChangeFile = document.getElementById('btnChangeFile');
  const btnAnalyze = document.getElementById('btnAnalyze');

  const loadingState = document.getElementById('loadingState');
  const errorMessage = document.getElementById('errorMessage');
  const errorTitle = document.getElementById('errorTitle');
  const errorText = document.getElementById('errorText');
  const resultsSection = document.getElementById('resultsSection');

  // Summary elements
  const scoreCircle = document.getElementById('scoreCircle');
  const riskScoreVal = document.getElementById('riskScoreVal');
  const riskLevelBadge = document.getElementById('riskLevelBadge');
  const confidenceBadge = document.getElementById('confidenceBadge');
  const metaFormat = document.getElementById('metaFormat');
  const metaDimensions = document.getElementById('metaDimensions');
  const summaryExplanation = document.getElementById('summaryExplanation');

  // Report Download Elements
  const btnShowReport = document.getElementById('btnShowReport');
  const btnShowReportText = document.getElementById('btnShowReportText');
  const reportDetailsSection = document.getElementById('reportDetailsSection');
  const btnDownloadReport = document.getElementById('btnDownloadReport');
  const btnDownloadJson = document.getElementById('btnDownloadJson');
  const downloadToast = document.getElementById('downloadToast');
  const toastMessage = document.getElementById('toastMessage');
  let toastTimeout = null;

  // Table elements
  const tableBody = document.getElementById('tableBody');
  const filterGroup = document.getElementById('filterGroup');
  const sortHeaders = document.querySelectorAll('.forensic-table th.sortable');

  // Hashes elements
  const hashSha256 = document.getElementById('hashSha256');
  const hashMd5 = document.getElementById('hashMd5');

  // Application State
  let currentFile = null;
  let analysisData = null;
  let activeFilter = 'all';
  let sortColumn = 'num';
  let sortDirection = 'asc'; // 'asc' or 'desc'

  const MAX_FILE_SIZE = 30 * 1024 * 1024; // 30 MB

  // -------------------------------------------------------------
  // File Selection & Drag-and-Drop
  // -------------------------------------------------------------
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('drag-active');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('drag-active');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
      handleFileSelected(files[0]);
    }
  });

  imageInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  btnChangeFile.addEventListener('click', (e) => {
    e.stopPropagation();
    imageInput.value = '';
    imageInput.click();
  });

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function handleFileSelected(file) {
    clearError();
    resultsSection.classList.add('hidden');

    if (!file) return;

    if (file.size > MAX_FILE_SIZE) {
      showError('File Too Large', `The selected file size (${formatFileSize(file.size)}) exceeds the 30 MB limit.`);
      return;
    }

    currentFile = file;

    // Update Preview UI safely
    previewFilename.textContent = file.name;
    previewFilesize.textContent = formatFileSize(file.size);

    const reader = new FileReader();
    reader.onload = (e) => {
      previewImg.src = e.target.result;
      dropzonePrompt.classList.add('hidden');
      filePreview.classList.remove('hidden');
      btnAnalyze.disabled = false;
    };
    reader.readAsDataURL(file);
  }

  // -------------------------------------------------------------
  // API Execution Pipeline
  // -------------------------------------------------------------
  btnAnalyze.addEventListener('click', () => {
    if (!currentFile) return;
    performAnalysis(currentFile);
  });

  async function performAnalysis(file) {
    clearError();
    resultsSection.classList.add('hidden');
    if (reportDetailsSection) reportDetailsSection.classList.add('hidden');
    if (btnShowReportText) btnShowReportText.textContent = 'Show Report';
    if (btnShowReport) btnShowReport.classList.remove('report-active');
    loadingState.classList.remove('hidden');
    btnAnalyze.disabled = true;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errDetail = 'Analysis request failed.';
        try {
          const errJson = await response.json();
          if (errJson && errJson.detail) {
            errDetail = errJson.detail;
          }
        } catch (_) {
          errDetail = `Server returned HTTP status ${response.status}: ${response.statusText}`;
        }
        throw new Error(errDetail);
      }

      const data = await response.json();
      analysisData = data;
      renderAnalysis(data);

    } catch (err) {
      showError('Forensic Analysis Error', err.message || 'An error occurred during image examination.');
    } finally {
      loadingState.classList.add('hidden');
      btnAnalyze.disabled = false;
    }
  }

  function showError(title, message) {
    errorTitle.textContent = title;
    errorText.textContent = message;
    errorMessage.classList.remove('hidden');
  }

  function clearError() {
    errorMessage.classList.add('hidden');
    errorTitle.textContent = '';
    errorText.textContent = '';
  }

  function showToast(msg) {
    if (!downloadToast || !toastMessage) return;
    toastMessage.textContent = msg;
    downloadToast.classList.remove('hidden');
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      downloadToast.classList.add('hidden');
    }, 4000);
  }

  // -------------------------------------------------------------
  // Results & Table Rendering (Security: No raw innerHTML injection)
  // -------------------------------------------------------------
  function getScoreColor(score) {
    if (score <= 20) return 'var(--risk-low)';
    if (score <= 40) return 'var(--risk-low-medium)';
    if (score <= 65) return 'var(--risk-inconclusive)';
    if (score <= 85) return 'var(--risk-high)';
    return 'var(--risk-very-high)';
  }

  function renderAnalysis(data) {
    // 1. Render Score Gauge
    const score = Number(data.risk_score) || 0;
    riskScoreVal.textContent = String(score);
    const scoreColor = getScoreColor(score);
    scoreCircle.style.borderColor = scoreColor;
    scoreCircle.style.boxShadow = `0 0 35px ${scoreColor}40`;

    // 2. Risk Level Badge
    riskLevelBadge.textContent = data.risk_level || 'Unknown';
    riskLevelBadge.style.color = scoreColor;
    riskLevelBadge.style.borderColor = scoreColor;

    // 3. Confidence Badge
    confidenceBadge.textContent = (data.confidence || 'Medium') + ` (${data.confidence_percentage || 0}%)`;
    if (data.confidence === 'High') {
      confidenceBadge.className = 'badge badge-lg badge-real';
    } else if (data.confidence === 'Low') {
      confidenceBadge.className = 'badge badge-lg badge-ai';
    } else {
      confidenceBadge.className = 'badge badge-lg badge-neutral';
    }

    // 4. Meta Attributes
    metaFormat.textContent = data.format || 'Unknown';
    metaDimensions.textContent = data.dimensions || 'Unknown';
    summaryExplanation.textContent = data.explanation || '';

    // 5. Technical Hashes
    hashSha256.textContent = data.sha256 || 'N/A';
    hashMd5.textContent = data.md5 || 'N/A';

    // 6. Build Forensic Results Table
    renderTable();

    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderTable() {
    if (!analysisData || !Array.isArray(analysisData.checks)) return;

    // Clear existing rows
    tableBody.innerHTML = '';

    // Attach original 1-based index (num) to each check
    const items = analysisData.checks.map((chk, idx) => ({
      ...chk,
      num: idx + 1,
    }));

    // Filter
    const filtered = items.filter(chk => {
      if (activeFilter === 'all') return true;
      if (activeFilter === 'ai') return chk.weight > 0 && chk.signal >= 0.7;
      if (activeFilter === 'real') return chk.weight > 0 && chk.signal <= 0.3;
      if (activeFilter === 'neutral') return chk.weight > 0 && chk.signal > 0.3 && chk.signal < 0.7;
      if (activeFilter === 'conclusive') return Boolean(chk.conclusive);
      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let valA = a[sortColumn];
      let valB = b[sortColumn];

      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();

      if (valA === undefined || valA === null) valA = '';
      if (valB === undefined || valB === null) valB = '';

      if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
      if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    // Populate rows
    filtered.forEach(chk => {
      const tr = document.createElement('tr');
      tr.className = 'table-row';

      // Subtle row highlight class
      if (chk.weight > 0) {
        if (chk.signal >= 0.8) tr.classList.add('row-ai-high');
        else if (chk.signal <= 0.2) tr.classList.add('row-real');
        else tr.classList.add('row-neutral');
      }

      // Column 1: #
      const tdNum = document.createElement('td');
      tdNum.className = 'td-num';
      tdNum.textContent = String(chk.num);
      tr.appendChild(tdNum);

      // Column 2: Forensic Check Title
      const tdTitle = document.createElement('td');
      tdTitle.className = 'td-check';
      tdTitle.textContent = chk.title || chk.key;
      tr.appendChild(tdTitle);

      // Column 3: Found
      const tdFound = document.createElement('td');
      tdFound.className = 'td-found';
      const foundBadge = document.createElement('span');
      foundBadge.className = 'badge';
      if (chk.found === true) {
        foundBadge.classList.add('badge-found-yes');
        foundBadge.textContent = 'Yes';
      } else if (chk.found === false) {
        foundBadge.classList.add('badge-found-no');
        foundBadge.textContent = 'No';
      } else {
        foundBadge.classList.add('badge-found-unknown');
        foundBadge.textContent = 'Unknown';
      }
      tdFound.appendChild(foundBadge);
      tr.appendChild(tdFound);

      // Column 4: Signal
      const tdSignal = document.createElement('td');
      tdSignal.className = 'td-signal';
      const signalBadge = document.createElement('span');
      signalBadge.className = 'badge';
      if (chk.weight === 0) {
        signalBadge.classList.add('badge-info');
        signalBadge.textContent = 'Informational';
      } else if (chk.signal >= 0.7) {
        signalBadge.classList.add('badge-ai');
        signalBadge.textContent = `AI-like (${chk.signal})`;
      } else if (chk.signal <= 0.3) {
        signalBadge.classList.add('badge-real');
        signalBadge.textContent = `Real-like (${chk.signal})`;
      } else {
        signalBadge.classList.add('badge-neutral');
        signalBadge.textContent = `Neutral (${chk.signal})`;
      }
      tdSignal.appendChild(signalBadge);
      tr.appendChild(tdSignal);

      // Column 5: Weight
      const tdWeight = document.createElement('td');
      tdWeight.className = 'td-weight';
      tdWeight.textContent = String(chk.weight);
      tr.appendChild(tdWeight);

      // Column 6: Points
      const tdPoints = document.createElement('td');
      tdPoints.className = 'td-points';
      tdPoints.textContent = String(chk.points);
      tr.appendChild(tdPoints);

      // Column 7: Evidence Text & Extra Details toggle
      const tdEvidence = document.createElement('td');
      tdEvidence.className = 'td-evidence';

      const evidenceSpan = document.createElement('span');
      evidenceSpan.textContent = chk.evidence || 'No evidence recorded.';
      tdEvidence.appendChild(evidenceSpan);

      // If check has detailed metadata, append expandable drawer
      if (chk.details && Object.keys(chk.details).length > 0) {
        const toggleBtn = document.createElement('span');
        toggleBtn.className = 'details-toggle';
        toggleBtn.textContent = 'details';

        const detailsBox = document.createElement('div');
        detailsBox.className = 'raw-details-box hidden';

        // Format details as readable key-value list safely
        const lines = Object.entries(chk.details).map(([k, v]) => {
          const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
          return `${k}: ${valStr}`;
        });
        detailsBox.textContent = lines.join('\n');

        toggleBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const isHidden = detailsBox.classList.contains('hidden');
          if (isHidden) {
            detailsBox.classList.remove('hidden');
            toggleBtn.textContent = 'hide';
          } else {
            detailsBox.classList.add('hidden');
            toggleBtn.textContent = 'details';
          }
        });

        tdEvidence.appendChild(toggleBtn);
        tdEvidence.appendChild(detailsBox);
      }

      tr.appendChild(tdEvidence);
      tableBody.appendChild(tr);
    });

    updateSortHeaderIcons();
  }

  // -------------------------------------------------------------
  // Table Sorting and Filtering Event Handlers
  // -------------------------------------------------------------
  filterGroup.addEventListener('click', (e) => {
    if (!e.target.classList.contains('filter-btn')) return;

    filterGroup.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    e.target.classList.add('active');
    activeFilter = e.target.getAttribute('data-filter') || 'all';
    renderTable();
  });

  sortHeaders.forEach(th => {
    th.addEventListener('click', () => {
      const col = th.getAttribute('data-sort');
      if (sortColumn === col) {
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
      } else {
        sortColumn = col;
        sortDirection = 'asc';
      }
      renderTable();
    });
  });

  function updateSortHeaderIcons() {
    sortHeaders.forEach(th => {
      const col = th.getAttribute('data-sort');
      const indicator = th.querySelector('.sort-indicator');
      if (!indicator) return;

      if (sortColumn === col) {
        indicator.textContent = sortDirection === 'asc' ? '▲' : '▼';
        th.style.color = 'var(--text-primary)';
      } else {
        indicator.textContent = '';
        th.style.color = '';
      }
    });
  }

  // -------------------------------------------------------------
  // Forensic Audit Report Toggle (Show / Hide Report)
  // -------------------------------------------------------------
  if (btnShowReport) {
    btnShowReport.addEventListener('click', (e) => {
      e.preventDefault();
      if (!analysisData) {
        showError('No Analysis Available', 'Please analyze an image first before viewing the report.');
        return;
      }
      if (!reportDetailsSection) return;

      const isHidden = reportDetailsSection.classList.contains('hidden');
      if (isHidden) {
        reportDetailsSection.classList.remove('hidden');
        if (btnShowReportText) btnShowReportText.textContent = 'Hide Report';
        btnShowReport.classList.add('report-active');
        reportDetailsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        reportDetailsSection.classList.add('hidden');
        if (btnShowReportText) btnShowReportText.textContent = 'Show Report';
        btnShowReport.classList.remove('report-active');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  }

  // -------------------------------------------------------------
  // Forensic Audit Report Generator (HTML & JSON)
  // -------------------------------------------------------------
  if (btnDownloadReport) {
    btnDownloadReport.addEventListener('click', (e) => {
      e.preventDefault();
      if (!analysisData) {
        showError('No Report Available', 'Please analyze an image first to generate the forensic report.');
        return;
      }
      downloadForensicHtmlReport(analysisData);
    });
  }

  if (btnDownloadJson) {
    btnDownloadJson.addEventListener('click', (e) => {
      e.preventDefault();
      if (!analysisData) {
        showError('No Data Available', 'Please analyze an image first to export forensic data.');
        return;
      }
      downloadForensicJson(analysisData);
    });
  }

  function sanitizeFilename(name) {
    return (name || 'image').replace(/[^a-zA-Z0-9_\-\.]/g, '_');
  }

  function downloadForensicJson(data) {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const safeName = sanitizeFilename(data.filename || 'image');
    link.href = url;
    link.download = `TruePic_Forensics_${safeName}.json`;
    link.setAttribute('target', '_blank');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 4000);
    showToast('Forensic JSON data exported successfully.');
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function downloadForensicHtmlReport(data) {
    const safeName = sanitizeFilename(data.filename || 'image');
    const timestamp = new Date().toISOString();
    const formattedDate = new Date().toUTCString();
    const shortHash = (data.sha256 || 'UNKNOWN').substring(0, 16);
    const reportScore = Number(data.risk_score) || 0;
    let reportScoreColor = '#15803d';
    if (reportScore > 20 && reportScore <= 40) reportScoreColor = '#16a34a';
    else if (reportScore > 40 && reportScore <= 65) reportScoreColor = '#d97706';
    else if (reportScore > 65 && reportScore <= 85) reportScoreColor = '#dc2626';
    else if (reportScore > 85) reportScoreColor = '#991b1b';

    const checksRowsHtml = (data.checks || []).map((chk, i) => {
      let foundText = 'Unknown';
      let foundColor = '#b45309';
      let foundBg = '#fffbeb';
      if (chk.found === true) {
        foundText = 'Yes';
        foundColor = '#15803d';
        foundBg = '#f0fdf4';
      } else if (chk.found === false) {
        foundText = 'No';
        foundColor = '#52525b';
        foundBg = '#f4f4f5';
      }

      let signalText = `Neutral (${chk.signal})`;
      let signalColor = '#52525b';
      let signalBg = '#f4f4f5';
      if (chk.weight === 0) {
        signalText = 'Informational';
        // Info signal colors (neutral gray) - replaced blue
        signalColor = '#52525b';
        signalBg = '#f4f4f5';
      } else if (chk.signal >= 0.7) {
        signalText = `AI-like (${chk.signal})`;
        signalColor = '#be123c';
        signalBg = '#fff1f2';
      } else if (chk.signal <= 0.3) {
        signalText = `Real-like (${chk.signal})`;
        signalColor = '#15803d';
        signalBg = '#f0fdf4';
      }

      let detailsBlock = '';
      if (chk.details && Object.keys(chk.details).length > 0) {
        const detailsLines = Object.entries(chk.details)
          .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(typeof v === 'object' ? JSON.stringify(v) : v)}`)
          .join('<br>');
        detailsBlock = `<div style="margin-top:6px; padding:6px 10px; background:#f4f4f5; border-radius:4px; font-family:'JetBrains Mono',monospace; font-size:11px; color:#52525b; line-height:1.4;">${detailsLines}</div>`;
      }

      return `
        <tr style="border-bottom: 1px solid #e4e4e7;">
          <td style="padding: 12px 14px; text-align: center; color: #71717a; font-family: 'JetBrains Mono', monospace; font-size: 12px;">${i + 1}</td>
          <td style="padding: 12px 14px; font-weight: 600; color: #09090b;">${escapeHtml(chk.title || chk.key)}</td>
          <td style="padding: 12px 14px; text-align: center;">
            <span style="display:inline-block; font-size:11px; font-weight:600; padding:2px 8px; border-radius:999px; background:${foundBg}; color:${foundColor};">${foundText}</span>
          </td>
          <td style="padding: 12px 14px; text-align: center;">
            <span style="display:inline-block; font-size:11px; font-weight:600; padding:2px 8px; border-radius:999px; background:${signalBg}; color:${signalColor};">${signalText}</span>
          </td>
          <td style="padding: 12px 14px; text-align: right; font-family: 'JetBrains Mono', monospace; font-size: 13px;">${chk.weight}</td>
          <td style="padding: 12px 14px; text-align: right; font-family: 'JetBrains Mono', monospace; font-weight: 600; font-size: 13px;">${chk.points}</td>
          <td style="padding: 12px 14px; font-size: 13px; color: #3f3f46; line-height: 1.45;">
            ${escapeHtml(chk.evidence || '')}
            ${detailsBlock}
          </td>
        </tr>
      `;
    }).join('');

    const reportHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TruePic Forensic Audit Report — ${escapeHtml(data.filename)}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #fafafa;
      color: #09090b;
      line-height: 1.55;
      padding: 40px 20px;
    }
    .report-sheet {
      max-width: 960px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #e4e4e7;
      border-radius: 12px;
      padding: 40px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
    }
    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding-bottom: 24px;
      border-bottom: 2px solid #09090b;
      margin-bottom: 28px;
    }
    .brand-title {
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .brand-sub {
      font-size: 13px;
      color: #71717a;
      margin-top: 2px;
    }
    .doc-meta {
      text-align: right;
      font-size: 12px;
      color: #52525b;
    }
    .doc-ref {
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      color: #09090b;
    }
    .print-bar {
      margin-bottom: 20px;
      display: flex;
      justify-content: flex-end;
    }
    .btn-print {
      background: #09090b;
      color: #ffffff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-print:hover { opacity: 0.9; }
    
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 28px;
    }
    .panel {
      background: #fcfcfc;
      border: 1px solid #e4e4e7;
      border-radius: 8px;
      padding: 18px 20px;
    }
    .panel-title {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #71717a;
      margin-bottom: 12px;
    }
    .kv-row {
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid #f4f4f5;
      font-size: 13px;
    }
    .kv-row:last-child { border-bottom: none; }
    .kv-k { color: #52525b; }
    .kv-v { font-weight: 600; color: #09090b; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    
    .score-banner {
      display: flex;
      align-items: center;
      gap: 24px;
      background: #f9fafb;
      border: 1px solid #e4e4e7;
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 28px;
    }
    .score-box {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      background: #ffffff;
      border: 4px solid ${reportScoreColor};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .score-val {
      font-size: 32px;
      font-weight: 800;
      letter-spacing: -0.04em;
      line-height: 1;
    }
    .score-tag {
      font-size: 9px;
      font-weight: 700;
      color: #71717a;
      margin-top: 2px;
      letter-spacing: 0.05em;
    }
    .score-meta h3 {
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 4px;
    }
    .score-desc {
      font-size: 13px;
      color: #52525b;
      line-height: 1.5;
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 10px;
    }
    th {
      background: #f4f4f5;
      padding: 10px 14px;
      text-align: left;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #52525b;
      border-bottom: 2px solid #e4e4e7;
    }
    
    .report-footer {
      margin-top: 36px;
      padding-top: 20px;
      border-top: 1px solid #e4e4e7;
      font-size: 11px;
      color: #71717a;
      line-height: 1.6;
    }

    @media print {
      body { background: #ffffff; padding: 0; }
      .report-sheet { border: none; box-shadow: none; padding: 0; }
      .print-bar { display: none; }
      tr { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="report-sheet">
    <div class="print-bar">
      <button type="button" class="btn-print" onclick="window.print()">Print / Save PDF</button>
    </div>

    <header class="report-header">
      <div>
        <h1 class="brand-title">TruePic Forensic Inspection Report</h1>
        <p class="brand-sub">Multi-Factor Image Authenticity & Synthetic Media Audit Dossier</p>
      </div>
      <div class="doc-meta">
        <div>Ref: <span class="doc-ref">TRP-${escapeHtml(shortHash)}</span></div>
        <div>Date: ${escapeHtml(formattedDate)}</div>
        <div>Standard: Heuristic v1.0.0</div>
      </div>
    </header>

    <div class="score-banner">
      <div class="score-box">
        <span class="score-val">${data.risk_score}</span>
        <span class="score-tag">RISK SCORE</span>
      </div>
      <div class="score-meta">
        <h3>Risk Assessment: ${escapeHtml(data.risk_level)} • Confidence: ${escapeHtml(data.confidence)} (${data.confidence_percentage}%)</h3>
        <p class="score-desc">${escapeHtml(data.explanation || 'Calculated from 100 active points across weighted forensic checks.')}</p>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-title">Target Image Profile</div>
        <div class="kv-row"><span class="kv-k">File Name</span><span class="kv-v">${escapeHtml(data.filename)}</span></div>
        <div class="kv-row"><span class="kv-k">File Size</span><span class="kv-v mono">${(data.filesize || 0).toLocaleString()} bytes</span></div>
        <div class="kv-row"><span class="kv-k">Dimensions</span><span class="kv-v mono">${escapeHtml(data.dimensions)}</span></div>
        <div class="kv-row"><span class="kv-k">Format / MIME</span><span class="kv-v">${escapeHtml(data.format)} (${escapeHtml(data.mime_type)})</span></div>
      </div>

      <div class="panel">
        <div class="panel-title">Cryptographic Integrity Hashes</div>
        <div class="kv-row" style="flex-direction: column; gap: 4px;">
          <span class="kv-k">SHA-256</span>
          <span class="kv-v mono" style="font-size: 11px; word-break: break-all;">${escapeHtml(data.sha256)}</span>
        </div>
        <div class="kv-row" style="flex-direction: column; gap: 4px; padding-top: 8px;">
          <span class="kv-k">MD5</span>
          <span class="kv-v mono" style="font-size: 11px; word-break: break-all;">${escapeHtml(data.md5)}</span>
        </div>
      </div>
    </div>

    <div>
      <h3 style="font-size: 14px; font-weight: 700; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.03em;">Forensic Checks & Evidence Matrix</h3>
      <table>
        <thead>
          <tr>
            <th style="width: 40px; text-align: center;">#</th>
            <th style="width: 170px;">Forensic Check</th>
            <th style="width: 80px; text-align: center;">Found</th>
            <th style="width: 120px; text-align: center;">Signal</th>
            <th style="width: 65px; text-align: right;">Weight</th>
            <th style="width: 65px; text-align: right;">Points</th>
            <th>Forensic Evidence & Metadata Parameters</th>
          </tr>
        </thead>
        <tbody>
          ${checksRowsHtml}
        </tbody>
      </table>
    </div>

    <footer class="report-footer">
      <p><strong>Heuristic Methodology Notice:</strong> TruePic evaluates digital imagery using independent multi-factor forensic heuristics spanning C2PA Content Credentials, generative diffusion metadata markers, optical sensor tags, and container integrity. Scores represent probabilistic indicators of artificial manipulation and do not constitute an infallible legal certificate. Digital custody verification should reference the SHA-256 hash provided above.</p>
    </footer>
  </div>
</body>
</html>`;

    const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `TruePic_Forensic_Report_${safeName}.html`;
    link.setAttribute('target', '_blank');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 4000);
    showToast('Forensic Audit Report downloaded successfully. Open to view or print as PDF.');
  }
});
