/* ========================================
   SHODAN VulnScopeX PRO v2.0
   Frontend JavaScript Utilities
   Theme Toggle, Animations, Helper Functions
   Organization: TeamCyberOps
   ======================================== */

// ==========================================
// API CONFIGURATION
// ==========================================
const API_BASE = 'http://localhost:5000/api/v4';

// Function to show notifications
function showMessage(message, type = 'info') {
  const alertDiv = document.createElement('div');
  alertDiv.className = `alert alert-${type === 'success' ? 'success' : type === 'error' ? 'danger' : type === 'warning' ? 'warning' : 'info'}`;
  alertDiv.style.position = 'fixed';
  alertDiv.style.top = '20px';
  alertDiv.style.right = '20px';
  alertDiv.style.zIndex = '9999';
  alertDiv.textContent = message;
  document.body.appendChild(alertDiv);
  setTimeout(() => alertDiv.remove(), 3000);
}

// ==========================================
// STUB FUNCTIONS FOR ALL GUI BUTTONS
// ==========================================

// Vulnerability CRUD
function createVulnerability() { showMessage('Creating vulnerability...', 'info'); }
function listVulnerabilities() { showMessage('Listing vulnerabilities...', 'info'); }
function searchVulnerabilities() { showMessage('Searching vulnerabilities...', 'info'); }
function filterVulnerabilities() { showMessage('Filtering vulnerabilities...', 'info'); }
function updateVulnerability() { showMessage('Updating vulnerability...', 'info'); }
function deleteVulnerability() { showMessage('Deleting vulnerability...', 'info'); }
function importVulnerabilities() { showMessage('Importing vulnerabilities...', 'info'); }
function batchUpdateVulns() { showMessage('Batch updating vulnerabilities...', 'info'); }

// Threat Intelligence
function getExploitDB() { showMessage('Loading exploit database...', 'info'); }
function getDefaultCreds() { showMessage('Loading default credentials...', 'info'); }
function generatePayloads() { showMessage('Generating payloads...', 'info'); }
function cveLookup() { showMessage('CVE lookup...', 'info'); }
function riskAssessment() { showMessage('Performing risk assessment...', 'info'); }
function affectedServices() { showMessage('Listing affected services...', 'info'); }
function getMitigations() { showMessage('Loading mitigations...', 'info'); }
function trendingThreats() { showMessage('Loading trending threats...', 'info'); }

// Analysis & Reporting
function getVulnStats() { showMessage('Loading vulnerability statistics...', 'info'); }
function analyzeCVSS() { showMessage('Analyzing CVSS scores...', 'info'); }
function trendAnalysis() { showMessage('Analyzing trends...', 'info'); }
function generateReport() { showMessage('Generating report...', 'info'); }
function affectedHosts() { showMessage('Loading affected hosts...', 'info'); }
function geoAnalysis() { showMessage('Performing geographic analysis...', 'info'); }

// Export Operations
function exportCSV() { showMessage('Exporting to CSV...', 'success'); window.location.href = API_BASE + '/export/csv'; }
function exportJSON() { showMessage('Exporting to JSON...', 'success'); window.location.href = API_BASE + '/export/json'; }
function exportPDF() { showMessage('Exporting to PDF...', 'success'); window.location.href = API_BASE + '/export/pdf'; }
function exportExcel() { showMessage('Exporting to Excel...', 'success'); window.location.href = API_BASE + '/export/excel'; }

// Asset Management
function createAsset() { showMessage('Creating asset...', 'info'); }
function listAssets() { showMessage('Listing assets...', 'info'); }
function viewAsset() { showMessage('Viewing asset...', 'info'); }
function updateAsset() { showMessage('Updating asset...', 'info'); }
function deleteAsset() { showMessage('Deleting asset...', 'info'); }

// Detection Rules
function createRule() { showMessage('Creating detection rule...', 'info'); }
function listRules() { showMessage('Listing detection rules...', 'info'); }
function updateRule() { showMessage('Updating rule...', 'info'); }
function deleteRule() { showMessage('Deleting rule...', 'info'); }
function testRule() { showMessage('Testing rule...', 'info'); }

// Payload Management
function addPayload() { showMessage('Adding payload...', 'info'); }
function listPayloads() { showMessage('Listing payloads...', 'info'); }
function genSQLi() { showMessage('Generating SQLi payload...', 'info'); }
function genXSS() { showMessage('Generating XSS payload...', 'info'); }
function genRCE() { showMessage('Generating RCE payload...', 'info'); }
function deletePayload() { showMessage('Deleting payload...', 'info'); }

// Audit & Logging
function getActivityLogs() { showMessage('Loading activity logs...', 'info'); }
function filterLogs() { showMessage('Filtering logs...', 'info'); }
function exportAudit() { showMessage('Exporting audit log...', 'success'); }
function clearLogs() { if(confirm('Clear all logs?')) showMessage('Logs cleared', 'success'); }
function getScanHistory() { showMessage('Loading scan history...', 'info'); }

// Scanner Operations
function pauseScan() { showMessage('Pausing scan...', 'warning'); }
function resumeScan() { showMessage('Resuming scan...', 'success'); }
function stopScan() { showMessage('Stopping scan...', 'warning'); }
function getScanStats() { showMessage('Loading scan statistics...', 'info'); }
function scheduleScan() { showMessage('Scheduling scan...', 'success'); }
function loadQueries() { showMessage('Loading queries...', 'info'); }
function saveScanTemplate() { showMessage('Saving template...', 'success'); }
function loadScanTemplate() { showMessage('Loading template...', 'info'); }

// Filters & Search
function filterBySeverity() { showMessage('Filtering by severity...', 'info'); }
function filterByService() { showMessage('Filtering by service...', 'info'); }
function filterByCountry() { showMessage('Filtering by country...', 'info'); }
function filterByPort() { showMessage('Filtering by port...', 'info'); }
function searchByIP() { showMessage('Searching by IP...', 'info'); }
function searchByOrg() { showMessage('Searching by organization...', 'info'); }
function searchByCVE() { showMessage('Searching by CVE...', 'info'); }
function advancedSearch() { showMessage('Advanced search...', 'info'); }

// Priority & Escalation
function setPriorityCritical() { showMessage('Setting priority to CRITICAL', 'warning'); }
function setPriorityHigh() { showMessage('Setting priority to HIGH', 'warning'); }
function setPriorityMedium() { showMessage('Setting priority to MEDIUM', 'info'); }
function setPriorityLow() { showMessage('Setting priority to LOW', 'success'); }
function escalateVuln() { showMessage('Escalating vulnerability...', 'warning'); }
function bulkPriority() { showMessage('Bulk priority update...', 'success'); }

// Remediation
function addPOC() { showMessage('Adding POC...', 'success'); }
function addRemediation() { showMessage('Adding remediation...', 'success'); }
function viewPOC() { showMessage('Viewing POC...', 'info'); }
function trackProgress() { showMessage('Tracking remediation progress...', 'info'); }
function markResolved() { showMessage('Marked as resolved', 'success'); }

// Batch Operations
function batchDelete() { showMessage('Batch deleting...', 'warning'); }
function batchExport() { showMessage('Batch exporting...', 'success'); }
function batchTag() { showMessage('Applying tags...', 'success'); }
function batchRescan() { showMessage('Batch rescanning...', 'info'); }
function selectAll() { showMessage('All items selected', 'info'); }
function deselectAll() { showMessage('All items deselected', 'info'); }

// Database Management
function purgeOldData() { showMessage('Purging old data...', 'warning'); }
function clearScanHistory() { showMessage('Clearing scan history...', 'warning'); }
function optimizeDB() { showMessage('Optimizing database...', 'info'); }
function getDatabaseStats() { showMessage('Loading database stats...', 'info'); }
function backupDB() { showMessage('Creating database backup...', 'success'); }
function restoreDB() { showMessage('Restoring database...', 'success'); }

// System & Health
function getHealthStatus() { showMessage('Checking system health...', 'info'); }
function getAPIInfo() { showMessage('Loading API information...', 'info'); }
function getDashboardMetrics() { showMessage('Loading dashboard metrics...', 'info'); }
function checkUpdates() { showMessage('Checking for updates...', 'info'); }
function getSystemInfo() { showMessage('Loading system information...', 'info'); }
function debugMode() { showMessage('Debug mode activated', 'info'); }

// Settings & Configuration
function configureAPI() { showMessage('API configuration...', 'info'); }
function setScanLimits() { showMessage('Setting scan limits...', 'success'); }
function setNotifications() { showMessage('Notification settings updated', 'success'); }
function setTheme() { showMessage('Theme settings updated', 'success'); }
function setLanguage() { showMessage('Language updated', 'success'); }
function resetSettings() { if(confirm('Reset all settings?')) showMessage('Settings reset', 'info'); }
function exportSettings() { showMessage('Exporting settings...', 'success'); }

// View & Display
function toggleCardView() { showMessage('Card view toggled', 'info'); }
function toggleTableView() { showMessage('Table view toggled', 'info'); }
function toggleMapView() { showMessage('Map view toggled', 'info'); }
function toggleChartView() { showMessage('Chart view toggled', 'info'); }
function zoomIn() { showMessage('Zoomed in', 'info'); }
function zoomOut() { showMessage('Zoomed out', 'info'); }
function toggleDarkMode() { showMessage('Dark mode toggled', 'info'); }
function refreshDisplay() { showMessage('Display refreshed', 'info'); }

// Quick Access
function favorites() { showMessage('Favorites loaded', 'info'); }
function recent() { showMessage('Recent scans loaded', 'info'); }
function bookmarks() { showMessage('Bookmarks loaded', 'info'); }
function quickReport() { showMessage('Quick report generated', 'success'); }
function savedSearches() { showMessage('Saved searches loaded', 'info'); }
function recentExports() { showMessage('Recent exports loaded', 'info'); }
function helpTutorial() { showMessage('Help tutorial opened', 'info'); }

// Advanced Features
function customQuery() { showMessage('Custom query builder opened', 'info'); }
function graphViewVulns() { showMessage('Graph visualization loaded', 'info'); }
function machineLearning() { showMessage('ML analysis initiated', 'success'); }
function integrations() { showMessage('Integrations panel opened', 'info'); }
function webhooks() { showMessage('Webhook configuration opened', 'info'); }
function automationRules() { showMessage('Automation rules editor opened', 'info'); }
function advancedFilters() { showMessage('Advanced filtering panel opened', 'info'); }
function customReports() { showMessage('Custom report builder opened', 'success'); }

// Additional Functions
function toggleSection(element) { 
  const section = element.closest('.control-section');
  if(section) section.classList.toggle('collapsed');
}

// ==========================================
// THEME MANAGEMENT
// ==========================================

class ThemeManager {
  constructor() {
    this.THEMES = {
      DARK: 'dark-theme',
      LIGHT: 'light-theme'
    };
    this.STORAGE_KEY = 'shodan_theme';
    this.init();
  }

  init() {
    this.loadTheme();
    this.createToggleButton();
    this.setupListeners();
  }

  loadTheme() {
    const savedTheme = localStorage.getItem(this.STORAGE_KEY);
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    const theme = savedTheme || (prefersDark ? this.THEMES.DARK : this.THEMES.LIGHT);
    this.setTheme(theme);
  }

  setTheme(theme) {
    document.body.classList.remove(this.THEMES.DARK, this.THEMES.LIGHT);
    document.body.classList.add(theme);
    localStorage.setItem(this.STORAGE_KEY, theme);
    this.updateToggleButton(theme);
  }

  toggleTheme() {
    const current = document.body.classList.contains(this.THEMES.DARK) 
      ? this.THEMES.DARK 
      : this.THEMES.LIGHT;
    const newTheme = current === this.THEMES.DARK ? this.THEMES.LIGHT : this.THEMES.DARK;
    this.setTheme(newTheme);
  }

  createToggleButton() {
    const button = document.createElement('button');
    button.className = 'theme-toggle';
    button.id = 'themeToggle';
    button.setAttribute('aria-label', 'Toggle theme');
    button.innerHTML = '🌙';
    document.body.appendChild(button);
  }

  updateToggleButton(theme) {
    const button = document.getElementById('themeToggle');
    if (button) {
      button.textContent = theme === this.THEMES.DARK ? '☀️' : '🌙';
    }
  }

  setupListeners() {
    const button = document.getElementById('themeToggle');
    if (button) {
      button.addEventListener('click', () => this.toggleTheme());
    }

    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem(this.STORAGE_KEY)) {
        this.setTheme(e.matches ? this.THEMES.DARK : this.THEMES.LIGHT);
      }
    });
  }
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

/**
 * Format bytes to human readable format
 */
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Format date to readable format
 */
function formatDate(date) {
  if (typeof date === 'string') {
    date = new Date(date);
  }
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Get severity color based on score
 */
function getSeverityColor(score) {
  if (score >= 9) return '#ff4444'; // CRITICAL (red)
  if (score >= 7) return '#ff8c42'; // HIGH (orange)
  if (score >= 4) return '#ffd700'; // MEDIUM (yellow)
  return '#4CAF50'; // LOW (green)
}

/**
 * Get severity label based on score
 */
function getSeverityLabel(score) {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text, feedback = true) {
  try {
    await navigator.clipboard.writeText(text);
    if (feedback) {
      showNotification('Copied to clipboard!', 'success');
    }
    return true;
  } catch (err) {
    console.error('Failed to copy:', err);
    if (feedback) {
      showNotification('Failed to copy', 'error');
    }
    return false;
  }
}

/**
 * Show notification/toast message
 */
function showNotification(message, type = 'info', duration = 3000) {
  const notification = document.createElement('div');
  notification.className = `alert alert-${type} fade-in`;
  notification.style.position = 'fixed';
  notification.style.top = '20px';
  notification.style.right = '20px';
  notification.style.zIndex = '9999';
  notification.style.minWidth = '300px';
  notification.style.maxWidth = '500px';

  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ'
  };

  notification.innerHTML = `
    <div class="alert-icon">${icons[type] || '•'}</div>
    <div class="alert-content">
      <div>${message}</div>
    </div>
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.animation = 'fadeOut 300ms ease';
    setTimeout(() => notification.remove(), 300);
  }, duration);

  return notification;
}

/**
 * Debounce function
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle function
 */
function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/**
 * Make API call
 */
async function apiCall(endpoint, options = {}) {
  const {
    method = 'GET',
    body = null,
    headers = {}
  } = options;

  const config = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers
    }
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(`/api/v2${endpoint}`, config);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || `API Error: ${response.status}`);
    }

    return { success: true, data };
  } catch (error) {
    console.error('API Error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Validate email
 */
function isValidEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

/**
 * Validate URL
 */
function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate unique ID
 */
function generateId() {
  return 'id_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Parse CSV
 */
function parseCSV(csvText) {
  const lines = csvText.trim().split('\n');
  const headers = lines[0].split(',').map(h => h.trim());
  const data = [];

  for (let i = 1; i < lines.length; i++) {
    const obj = {};
    const fields = lines[i].split(',');
    headers.forEach((header, index) => {
      obj[header] = fields[index]?.trim() || '';
    });
    data.push(obj);
  }

  return data;
}

/**
 * Export to CSV
 */
function exportToCSV(data, filename = 'export.csv') {
  if (!data || data.length === 0) {
    showNotification('No data to export', 'warning');
    return;
  }

  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(','),
    ...data.map(row =>
      headers.map(header =>
        JSON.stringify(row[header] || '')
      ).join(',')
    )
  ].join('\n');

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  window.URL.revokeObjectURL(url);

  showNotification('CSV exported successfully', 'success');
}

/**
 * Export to JSON
 */
function exportToJSON(data, filename = 'export.json') {
  if (!data || (Array.isArray(data) && data.length === 0)) {
    showNotification('No data to export', 'warning');
    return;
  }

  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  window.URL.revokeObjectURL(url);

  showNotification('JSON exported successfully', 'success');
}

/**
 * Sort array of objects
 */
function sortBy(array, key, descending = false) {
  return [...array].sort((a, b) => {
    const aVal = a[key];
    const bVal = b[key];

    if (aVal < bVal) return descending ? 1 : -1;
    if (aVal > bVal) return descending ? -1 : 1;
    return 0;
  });
}

/**
 * Filter array of objects
 */
function filterBy(array, key, value) {
  return array.filter(item => item[key] === value);
}

/**
 * Get unique values from array property
 */
function getUnique(array, key) {
  return [...new Set(array.map(item => item[key]))];
}

/**
 * Make table row clickable
 */
function makeTableClickable(tableSelector, callback) {
  const table = document.querySelector(tableSelector);
  if (!table) return;

  table.querySelectorAll('tbody tr').forEach(row => {
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {
      const data = {};
      const cells = row.querySelectorAll('td');
      const headers = table.querySelectorAll('thead th');

      headers.forEach((header, index) => {
        const key = header.textContent.trim().toLowerCase().replace(/\s+/g, '_');
        data[key] = cells[index]?.textContent.trim() || '';
      });

      callback(data, row);
    });
  });
}

/**
 * Initialize tooltips
 */
function initTooltips() {
  const tooltips = document.querySelectorAll('[data-tooltip]');
  tooltips.forEach(element => {
    element.addEventListener('mouseover', function() {
      const tooltip = document.createElement('div');
      tooltip.className = 'tooltip';
      tooltip.textContent = this.dataset.tooltip;
      tooltip.style.position = 'absolute';
      tooltip.style.background = 'rgba(0, 0, 0, 0.8)';
      tooltip.style.color = 'white';
      tooltip.style.padding = '6px 12px';
      tooltip.style.borderRadius = '4px';
      tooltip.style.fontSize = '12px';
      tooltip.style.zIndex = '1000';
      tooltip.style.whiteSpace = 'nowrap';
      
      document.body.appendChild(tooltip);

      const rect = this.getBoundingClientRect();
      tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
      tooltip.style.top = (rect.top - tooltip.offsetHeight - 8) + 'px';
    });

    element.addEventListener('mouseout', () => {
      const tooltips = document.querySelectorAll('.tooltip');
      tooltips.forEach(t => t.remove());
    });
  });
}

/**
 * Initialize loading spinner
 */
function showLoading(element, show = true) {
  if (show) {
    element.innerHTML = '<div class="spin" style="text-align: center; padding: 20px;">⏳ Loading...</div>';
  } else {
    element.innerHTML = '';
  }
}

/**
 * Confirm dialog
 */
function confirmDialog(message) {
  return new Promise((resolve) => {
    if (confirm(message)) {
      resolve(true);
    } else {
      resolve(false);
    }
  });
}

/**
 * Countdown timer
 */
function startCountdown(seconds, callback) {
  let remaining = seconds;
  const interval = setInterval(() => {
    remaining--;
    callback(remaining);
    if (remaining <= 0) {
      clearInterval(interval);
    }
  }, 1000);
}

/**
 * Format phone number
 */
function formatPhone(phone) {
  const cleaned = phone.replace(/\D/g, '');
  const match = cleaned.match(/^(\d{3})(\d{3})(\d{4})$/);
  if (match) {
    return `(${match[1]}) ${match[2]}-${match[3]}`;
  }
  return phone;
}

/**
 * Highlight text
 */
function highlightText(text, query) {
  if (!query) return text;
  const regex = new RegExp(`(${query})`, 'gi');
  return text.replace(regex, '<mark>$1</mark>');
}

/**
 * Get browser info
 */
function getBrowserInfo() {
  const ua = navigator.userAgent;
  return {
    userAgent: ua,
    isMobile: /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua),
    isChrome: /Chrome/.test(ua),
    isFirefox: /Firefox/.test(ua),
    isSafari: /Safari/.test(ua),
    isEdge: /Edg/.test(ua)
  };
}

/**
 * Check if element is in viewport
 */
function isInViewport(element) {
  const rect = element.getBoundingClientRect();
  return (
    rect.top >= 0 &&
    rect.left >= 0 &&
    rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
    rect.right <= (window.innerWidth || document.documentElement.clientWidth)
  );
}

/**
 * Scroll to element
 */
function scrollToElement(selector, offset = 0) {
  const element = document.querySelector(selector);
  if (element) {
    const top = element.getBoundingClientRect().top + window.scrollY - offset;
    window.scrollTo({ top, behavior: 'smooth' });
  }
}

// ════════════════════════════════════════════════════════════════
// FEATURE BUTTON EVENT HANDLERS - VULNERABILITY MANAGEMENT
// ════════════════════════════════════════════════════════════════

async function createVulnerability() {
  const target = prompt('Enter target IP/hostname:');
  if (!target) return;
  const cve = prompt('Enter CVE ID (optional):', '');
  const priority = prompt('Enter priority (CRITICAL/HIGH/MEDIUM/LOW):', 'MEDIUM');
  const description = prompt('Enter description:', '');
  
  const result = await apiCall('/vulns', {
    method: 'POST',
    body: { target, cve_id: cve || null, priority, description }
  });
  
  if (result.success) {
    showNotification('✅ Vulnerability created', 'success');
    await listVulnerabilities();
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function listVulnerabilities() {
  const result = await apiCall('/vulns');
  if (result.success) {
    const vulns = result.data.vulnerabilities || [];
    displayResults('vulnerabilityResults', vulns, 'Vulnerabilities');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function searchVulnerabilities() {
  const query = prompt('Enter search term:');
  if (!query) return;
  
  const result = await apiCall('/vulns/search?q=' + encodeURIComponent(query));
  if (result.success) {
    displayResults('vulnerabilityResults', result.data.results || [], 'Search Results');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function filterVulnerabilities() {
  const severity = prompt('Filter by severity (CRITICAL/HIGH/MEDIUM/LOW) or leave empty:', '');
  const service = prompt('Filter by service (optional):', '');
  
  const result = await apiCall('/vulns/filter', {
    method: 'POST',
    body: { severity: severity || null, service: service || null }
  });
  
  if (result.success) {
    displayResults('vulnerabilityResults', result.data.vulnerabilities || [], 'Filtered Results');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function updateVulnerability() {
  const id = prompt('Enter vulnerability ID:');
  if (!id) return;
  const priority = prompt('Enter new priority:', '');
  const status = prompt('Enter new status:', '');
  
  const result = await apiCall(`/vulns/${id}`, {
    method: 'PUT',
    body: { priority: priority || undefined, status: status || undefined }
  });
  
  if (result.success) {
    showNotification('✅ Vulnerability updated', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function deleteVulnerability() {
  const id = prompt('Enter vulnerability ID to delete:');
  if (!id || !confirm('Are you sure?')) return;
  
  const result = await apiCall(`/vulns/${id}`, { method: 'DELETE' });
  if (result.success) {
    showNotification('✅ Vulnerability deleted', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function importVulnerabilities() {
  alert('Upload CSV file with columns: target, cve_id, priority, description');
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.csv';
  input.onchange = async (e) => {
    const file = e.target.files[0];
    const text = await file.text();
    const result = await apiCall('/vulns/from-csv', {
      method: 'POST',
      body: { csv_content: text }
    });
    if (result.success) {
      showNotification('✅ Imported ' + result.data.imported + ' vulnerabilities', 'success');
    } else {
      showNotification('❌ Error: ' + result.error, 'error');
    }
  };
  input.click();
}

async function batchUpdateVulns() {
  const action = prompt('Enter action (SET_PRIORITY/SET_STATUS/ADD_TAG):', '');
  const value = prompt('Enter value:', '');
  
  const result = await apiCall('/vulns/batch-update', {
    method: 'POST',
    body: { action, value }
  });
  
  if (result.success) {
    showNotification('✅ Batch updated ' + result.data.count + ' records', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE BUTTONS
// ════════════════════════════════════════════════════════════════

async function getExploitDB() {
  const result = await apiCall('/threat/exploit-db');
  if (result.success) {
    displayResults('threatResults', result.data.exploits || [], 'Exploit Database');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getDefaultCreds() {
  const result = await apiCall('/threat/default-creds');
  if (result.success) {
    displayResults('threatResults', result.data.credentials || [], 'Default Credentials');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function generatePayloads() {
  const type = prompt('Payload type (SQLi/XSS/RCE/NoSQL/LDAP/CMD):', 'SQLi');
  if (!type) return;
  
  const result = await apiCall('/threat/payloads', {
    method: 'POST',
    body: { payload_type: type }
  });
  
  if (result.success) {
    displayResults('threatResults', result.data.payloads || [], 'Generated Payloads');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function cveLookup() {
  const cve = prompt('Enter CVE ID (e.g., CVE-2023-1234):');
  if (!cve) return;
  
  const result = await apiCall('/threat/cve-lookup?cve=' + encodeURIComponent(cve));
  if (result.success) {
    showNotification('✅ CVE ' + cve + ': ' + result.data.description, 'success');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function riskAssessment() {
  const target = prompt('Enter target IP/hostname:');
  if (!target) return;
  
  const result = await apiCall('/threat/risk-assessment', {
    method: 'POST',
    body: { target }
  });
  
  if (result.success) {
    showNotification('Risk Score: ' + result.data.risk_score, 'info');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function affectedServices() {
  const result = await apiCall('/threat/affected-services');
  if (result.success) {
    displayResults('threatResults', result.data.services || [], 'Affected Services');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getMitigations() {
  const cve = prompt('Enter CVE ID for mitigation strategies:');
  if (!cve) return;
  
  const result = await apiCall('/threat/mitigations?cve=' + encodeURIComponent(cve));
  if (result.success) {
    displayResults('threatResults', result.data.mitigations || [], 'Mitigation Strategies');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function trendingThreats() {
  const result = await apiCall('/threat/trending');
  if (result.success) {
    displayResults('threatResults', result.data.threats || [], 'Trending Threats');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// ANALYSIS & REPORTING BUTTONS
// ════════════════════════════════════════════════════════════════

async function getVulnStats() {
  const result = await apiCall('/analyze/stats');
  if (result.success) {
    const stats = result.data;
    const summary = `
      Total: ${stats.total_vulns}
      Critical: ${stats.critical} | High: ${stats.high} | Medium: ${stats.medium} | Low: ${stats.low}
      Average Score: ${stats.avg_score}
    `;
    showNotification(summary, 'info');
    console.log(stats);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function analyzeCVSS() {
  const result = await apiCall('/analyze/cvss');
  if (result.success) {
    displayResults('analysisResults', result.data.analysis || [], 'CVSS Analysis');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function analyzeTrends() {
  const result = await apiCall('/analyze/trends');
  if (result.success) {
    console.log(result.data);
    showNotification('Trend data loaded - check console', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function generateReport() {
  const result = await apiCall('/analyze/report', {
    method: 'POST',
    body: { format: 'json' }
  });
  
  if (result.success) {
    showNotification('✅ Report generated', 'success');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getAffectedHosts() {
  const result = await apiCall('/analyze/affected-hosts');
  if (result.success) {
    displayResults('analysisResults', result.data.hosts || [], 'Affected Hosts');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getRiskMap() {
  const result = await apiCall('/analyze/risk-map');
  if (result.success) {
    console.log('Risk Distribution:', result.data);
    showNotification('Risk map generated - check console', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// EXPORT BUTTONS
// ════════════════════════════════════════════════════════════════

async function exportCSV() {
  try {
    const response = await fetch('/api/v2/export/csv');
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerabilities_' + new Date().getTime() + '.csv';
    a.click();
    showNotification('✅ CSV exported', 'success');
  } catch (error) {
    showNotification('❌ Error: ' + error.message, 'error');
  }
}

async function exportJSON() {
  const result = await apiCall('/export/json');
  if (result.success) {
    const json = JSON.stringify(result.data, null, 2);
    downloadFile(json, 'vulnerabilities_' + Date.now() + '.json', 'application/json');
    showNotification('✅ JSON exported', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function exportPDF() {
  try {
    const response = await fetch('/api/v2/export/pdf');
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerabilities_' + Date.now() + '.pdf';
    a.click();
    showNotification('✅ PDF exported', 'success');
  } catch (error) {
    showNotification('❌ Error: ' + error.message, 'error');
  }
}

async function exportExcel() {
  try {
    const response = await fetch('/api/v2/export/excel');
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerabilities_' + Date.now() + '.xlsx';
    a.click();
    showNotification('✅ Excel exported', 'success');
  } catch (error) {
    showNotification('❌ Error: ' + error.message, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// ASSET MANAGEMENT BUTTONS
// ════════════════════════════════════════════════════════════════

async function createAsset() {
  const ip = prompt('Enter IP address:');
  if (!ip) return;
  const hostname = prompt('Enter hostname (optional):', '');
  const country = prompt('Enter country (optional):', '');
  
  const result = await apiCall('/assets/add', {
    method: 'POST',
    body: { ip_address: ip, hostname: hostname || null, country: country || null }
  });
  
  if (result.success) {
    showNotification('✅ Asset created', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function listAssets() {
  const result = await apiCall('/assets');
  if (result.success) {
    displayResults('assetResults', result.data.assets || [], 'Assets');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getAsset() {
  const ip = prompt('Enter IP address:');
  if (!ip) return;
  
  const result = await apiCall(`/assets/${ip}`);
  if (result.success) {
    showNotification('Asset found - check console', 'success');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function updateAsset() {
  const ip = prompt('Enter IP address:');
  if (!ip) return;
  const hostname = prompt('Enter new hostname:', '');
  const country = prompt('Enter new country:', '');
  
  const result = await apiCall(`/assets/${ip}`, {
    method: 'PUT',
    body: { hostname: hostname || undefined, country: country || undefined }
  });
  
  if (result.success) {
    showNotification('✅ Asset updated', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function deleteAsset() {
  const ip = prompt('Enter IP address to delete:');
  if (!ip || !confirm('Delete this asset?')) return;
  
  const result = await apiCall(`/assets/${ip}`, { method: 'DELETE' });
  if (result.success) {
    showNotification('✅ Asset deleted', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// DETECTION RULES BUTTONS
// ════════════════════════════════════════════════════════════════

async function createRule() {
  const name = prompt('Enter rule name:');
  if (!name) return;
  const pattern = prompt('Enter detection pattern (regex):');
  const severity = prompt('Enter severity (CRITICAL/HIGH/MEDIUM/LOW):', 'MEDIUM');
  
  const result = await apiCall('/rules/create', {
    method: 'POST',
    body: { name, pattern, severity }
  });
  
  if (result.success) {
    showNotification('✅ Rule created', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function listRules() {
  const result = await apiCall('/rules');
  if (result.success) {
    displayResults('rulesResults', result.data.rules || [], 'Detection Rules');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function updateRule() {
  const id = prompt('Enter rule ID:');
  if (!id) return;
  const name = prompt('Enter new name:', '');
  const pattern = prompt('Enter new pattern:', '');
  const severity = prompt('Enter new severity:', '');
  
  const result = await apiCall(`/rules/${id}`, {
    method: 'PUT',
    body: { name: name || undefined, pattern: pattern || undefined, severity: severity || undefined }
  });
  
  if (result.success) {
    showNotification('✅ Rule updated', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function deleteRule() {
  const id = prompt('Enter rule ID to delete:');
  if (!id || !confirm('Delete this rule?')) return;
  
  const result = await apiCall(`/rules/${id}`, { method: 'DELETE' });
  if (result.success) {
    showNotification('✅ Rule deleted', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function testRule() {
  const ruleId = prompt('Enter rule ID:');
  const testData = prompt('Enter test data:');
  if (!ruleId || !testData) return;
  
  const result = await apiCall('/rules/test', {
    method: 'POST',
    body: { rule_id: ruleId, test_data: testData }
  });
  
  if (result.success) {
    showNotification(result.data.matches ? '✅ Rule matches!' : '⚠️ No match', 'info');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// PAYLOAD MANAGEMENT BUTTONS
// ════════════════════════════════════════════════════════════════

async function addPayload() {
  const type = prompt('Payload type (SQLi/XSS/RCE/NoSQL/LDAP/CMD):', '');
  const content = prompt('Payload content:', '');
  if (!type || !content) return;
  
  const result = await apiCall('/payloads/add', {
    method: 'POST',
    body: { type, content }
  });
  
  if (result.success) {
    showNotification('✅ Payload added', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function listPayloads() {
  const result = await apiCall('/payloads');
  if (result.success) {
    displayResults('payloadResults', result.data.payloads || [], 'Payload Library');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function genSQLi() {
  const result = await apiCall('/payloads/generate?type=sqli');
  if (result.success) {
    displayResults('payloadResult', result.data.payloads || [], 'SQLi Payloads');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function genXSS() {
  const result = await apiCall('/payloads/generate?type=xss');
  if (result.success) {
    displayResults('payloadResults', result.data.payloads || [], 'XSS Payloads');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function genRCE() {
  const result = await apiCall('/payloads/generate?type=rce');
  if (result.success) {
    displayResults('payloadResults', result.data.payloads || [], 'RCE Payloads');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function deletePayload() {
  const id = prompt('Enter payload ID:');
  if (!id || !confirm('Delete this payload?')) return;
  
  const result = await apiCall(`/payloads/${id}`, { method: 'DELETE' });
  if (result.success) {
    showNotification('✅ Payload deleted', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// LOGGING & AUDIT BUTTONS
// ════════════════════════════════════════════════════════════════

async function getActivityLogs() {
  const result = await apiCall('/logs');
  if (result.success) {
    displayResults('logResults', result.data.logs || [], 'Activity Logs');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function filterLogs() {
  const action = prompt('Filter by action (CREATE/UPDATE/DELETE/etc):');
  if (!action) return;
  
  const result = await apiCall('/logs/filter', {
    method: 'POST',
    body: { action }
  });
  
  if (result.success) {
    displayResults('logResults', result.data.logs || [], 'Filtered Logs');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function exportAudit() {
  try {
    const response = await fetch('/api/v2/export/audit');
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit_' + Date.now() + '.csv';
    a.click();
    showNotification('✅ Audit log exported', 'success');
  } catch (error) {
    showNotification('❌ Error: ' + error.message, 'error');
  }
}

async function clearLogs() {
  if (!confirm('Clear all logs? This cannot be undone!')) return;
  
  const result = await apiCall('/logs/clear', { method: 'POST' });
  if (result.success) {
    showNotification('✅ Logs cleared', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getScanHistory() {
  const result = await apiCall('/logs/scan-history');
  if (result.success) {
    displayResults('logResults', result.data.history || [], 'Scan History');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// SCANNER OPERATIONS BUTTONS
// ════════════════════════════════════════════════════════════════

async function pauseScan() {
  const result = await apiCall('/scan/pause');
  if (result.success) {
    showNotification('✅ Scan paused', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function resumeScan() {
  const result = await apiCall('/scan/resume');
  if (result.success) {
    showNotification('✅ Scan resumed', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function stopScan() {
  const result = await apiCall('/scan/stop');
  if (result.success) {
    showNotification('✅ Scan stopped', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function getScanStats() {
  const result = await apiCall('/scan/stats');
  if (result.success) {
    const stats = result.data;
    const summary = `Scanned: ${stats.scanned} | Found: ${stats.found} | Duration: ${stats.duration}s`;
    showNotification(summary, 'success');
    console.log(stats);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function scheduleScan() {
  const query = prompt('Enter SHODAN query:');
  const time = prompt('Schedule at (HH:MM format):');
  if (!query || !time) return;
  
  const result = await apiCall('/scan/schedule', {
    method: 'POST',
    body: { query, scheduled_time: time }
  });
  
  if (result.success) {
    showNotification('✅ Scan scheduled', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function loadQueries() {
  const result = await apiCall('/scan/categories');
  if (result.success) {
    displayResults('queriesResults', result.data.categories || [], 'Query Categories');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function saveScanTemplate() {
  const name = prompt('Template name:');
  const query = prompt('SHODAN query:');
  if (!name || !query) return;
  
  const result = await apiCall('/scan/template/save', {
    method: 'POST',
    body: { name, query }
  });
  
  if (result.success) {
    showNotification('✅ Template saved', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function loadScanTemplate() {
  const result = await apiCall('/scan/templates');
  if (result.success) {
    displayResults('templateResults', result.data.templates || [], 'Saved Templates');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// FILTER & SEARCH BUTTONS
// ════════════════════════════════════════════════════════════════

async function filterBySeverity() {
  const severity = prompt('Enter severity (CRITICAL/HIGH/MEDIUM/LOW):', '');
  if (!severity) return;
  
  const result = await apiCall(`/vulns/filter?severity=${severity}`);
  if (result.success) {
    displayResults('filterResults', result.data.vulnerabilities || [], `${severity} Severity`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function filterByService() {
  const service = prompt('Enter service name:');
  if (!service) return;
  
  const result = await apiCall(`/vulns/filter?service=${encodeURIComponent(service)}`);
  if (result.success) {
    displayResults('filterResults', result.data.vulnerabilities || [], `Service: ${service}`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function filterByCountry() {
  const country = prompt('Enter country code (e.g., US, CN):');
  if (!country) return;
  
  const result = await apiCall(`/vulns/filter?country=${country}`);
  if (result.success) {
    displayResults('filterResults', result.data.vulnerabilities || [], `Country: ${country}`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function filterByPort() {
  const port = prompt('Enter port number:');
  if (!port) return;
  
  const result = await apiCall(`/vulns/filter?port=${port}`);
  if (result.success) {
    displayResults('filterResults', result.data.vulnerabilities || [], `Port: ${port}`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function searchByIP() {
  const ip = prompt('Enter IP address:');
  if (!ip) return;
  
  const result = await apiCall(`/vulns/search?ip=${ip}`);
  if (result.success) {
    displayResults('filterResults', result.data.results || [], `IP: ${ip}`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function searchByOrg() {
  const org = prompt('Enter organization name:');
  if (!org) return;
  
  const result = await apiCall(`/vulns/search?org=${encodeURIComponent(org)}`);
  if (result.success) {
    displayResults('filterResults', result.data.results || [], `Organization: ${org}`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function searchByCVE() {
  const cve = prompt('Enter CVE ID:');
  if (!cve) return;
  
  const result = await apiCall(`/vulns/search?cve=${cve}`);
  if (result.success) {
    displayResults('filterResults', result.data.results || [], `CVE: ${cve}`);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function advancedSearch() {
  alert('Advanced Search: Enter multiple filters separated by &');
  const filters = prompt('Filters (e.g., severity=CRITICAL&service=SSH):', '');
  if (!filters) return;
  
  const result = await apiCall(`/vulns/search?${filters}`);
  if (result.success) {
    displayResults('filterResults', result.data.results || [], 'Advanced Search Results');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// PRIORITY & ESCALATION BUTTONS
// ════════════════════════════════════════════════════════════════

async function setPriorityCritical() {
  const id = prompt('Enter vulnerability ID:');
  if (!id) return;
  
  const result = await apiCall(`/vulns/${id}/priority`, {
    method: 'PATCH',
    body: { priority: 'CRITICAL' }
  });
  
  if (result.success) {
    showNotification('✅ Priority set to CRITICAL', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function setPriorityHigh() {
  const id = prompt('Enter vulnerability ID:');
  if (!id) return;
  
  const result = await apiCall(`/vulns/${id}/priority`, {
    method: 'PATCH',
    body: { priority: 'HIGH' }
  });
  
  if (result.success) {
    showNotification('✅ Priority set to HIGH', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function setPriorityMedium() {
  const id = prompt('Enter vulnerability ID:');
  if (!id) return;
  
  const result = await apiCall(`/vulns/${id}/priority`, {
    method: 'PATCH',
    body: { priority: 'MEDIUM' }
  });
  
  if (result.success) {
    showNotification('✅ Priority set to MEDIUM', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function setPriorityLow() {
  const id = prompt('Enter vulnerability ID:');
  if (!id) return;
  
  const result = await apiCall(`/vulns/${id}/priority`, {
    method: 'PATCH',
    body: { priority: 'LOW' }
  });
  
  if (result.success) {
    showNotification('✅ Priority set to LOW', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function escalateVuln() {
  const id = prompt('Enter vulnerability ID:');
  if (!id) return;
  
  const result = await apiCall(`/vulns/${id}/escalate`, { method: 'POST' });
  if (result.success) {
    showNotification('✅ Vulnerability escalated', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function bulkPriority() {
  const priority = prompt('Set priority to (CRITICAL/HIGH/MEDIUM/LOW):');
  if (!priority) return;
  
  const result = await apiCall('/vulns/bulk-priority', {
    method: 'POST',
    body: { priority }
  });
  
  if (result.success) {
    showNotification('✅ Updated ' + result.data.count + ' records', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// REMEDIATION BUTTONS
// ════════════════════════════════════════════════════════════════

async function addPOC() {
  const vulnId = prompt('Enter vulnerability ID:');
  const poc = prompt('Enter proof of concept code/description:');
  if (!vulnId || !poc) return;
  
  const result = await apiCall(`/vulns/${vulnId}/poc`, {
    method: 'POST',
    body: { proof_of_concept: poc }
  });
  
  if (result.success) {
    showNotification('✅ POC added', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function addRemediation() {
  const vulnId = prompt('Enter vulnerability ID:');
  const remediation = prompt('Enter remediation steps:');
  if (!vulnId || !remediation) return;
  
  const result = await apiCall(`/vulns/${vulnId}/remediation`, {
    method: 'POST',
    body: { remediation }
  });
  
  if (result.success) {
    showNotification('✅ Remediation added', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function viewPOC() {
  const vulnId = prompt('Enter vulnerability ID:');
  if (!vulnId) return;
  
  const result = await apiCall(`/vulns/${vulnId}/poc`);
  if (result.success) {
    showNotification('POC: ' + result.data.proof_of_concept, 'info');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function trackProgress() {
  const vulnId = prompt('Enter vulnerability ID:');
  if (!vulnId) return;
  
  const result = await apiCall(`/vulns/${vulnId}/progress`);
  if (result.success) {
    showNotification('Progress: ' + result.data.progress + '%', 'info');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function markResolved() {
  const vulnId = prompt('Enter vulnerability ID:');
  if (!vulnId) return;
  
  const result = await apiCall(`/vulns/${vulnId}/resolve`, { method: 'POST' });
  if (result.success) {
    showNotification('✅ Marked as resolved', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// INTELLIGENCE & ANALYTICS BUTTONS
// ════════════════════════════════════════════════════════════════

async function correlateVulns() {
  const result = await apiCall('/analyze/correlate');
  if (result.success) {
    displayResults('analyticsResults', result.data.correlations || [], 'Vulnerability Correlations');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function geoAnalysis() {
  const result = await apiCall('/analyze/geo');
  if (result.success) {
    console.log('Geographic Distribution:', result.data);
    showNotification('Geo analysis complete - check console', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function serviceAnalysis() {
  const result = await apiCall('/analyze/services');
  if (result.success) {
    displayResults('analyticsResults', result.data.services || [], 'Service Breakdown');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function riskTimeline() {
  const result = await apiCall('/analyze/timeline');
  if (result.success) {
    console.log('Risk Timeline:', result.data);
    showNotification('Timeline analysis complete - check console', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function topTargets() {
  const result = await apiCall('/analyze/top-targets');
  if (result.success) {
    displayResults('analyticsResults', result.data.targets || [], 'Top Vulnerable Targets');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function outliers() {
  const result = await apiCall('/analyze/outliers');
  if (result.success) {
    displayResults('analyticsResults', result.data.anomalies || [], 'Anomalies Detected');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function predictRisk() {
  const result = await apiCall('/analyze/predict');
  if (result.success) {
    showNotification('Risk Prediction: ' + result.data.prediction, 'info');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// BATCH OPERATIONS BUTTONS
// ════════════════════════════════════════════════════════════════

async function batchDelete() {
  const ids = prompt('Enter IDs to delete (comma-separated):');
  if (!ids || !confirm('Delete these items? This cannot be undone!')) return;
  
  const result = await apiCall('/vulns/batch-delete', {
    method: 'POST',
    body: { ids: ids.split(',').map(id => id.trim()) }
  });
  
  if (result.success) {
    showNotification('✅ Deleted ' + result.data.count + ' items', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function batchExport() {
  const ids = prompt('Enter IDs to export (comma-separated):');
  const format = prompt('Format (csv/json/pdf):', 'json');
  if (!ids) return;
  
  const result = await apiCall('/vulns/batch-export', {
    method: 'POST',
    body: { ids: ids.split(',').map(id => id.trim()), format }
  });
  
  if (result.success) {
    const json = JSON.stringify(result.data, null, 2);
    downloadFile(json, `export_${Date.now()}.${format}`, 'application/json');
    showNotification('✅ Exported', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function batchTag() {
  const ids = prompt('Enter IDs to tag (comma-separated):');
  const tag = prompt('Enter tag name:');
  if (!ids || !tag) return;
  
  const result = await apiCall('/vulns/batch-tag', {
    method: 'POST',
    body: { ids: ids.split(',').map(id => id.trim()), tag }
  });
  
  if (result.success) {
    showNotification('✅ Tagged ' + result.data.count + ' items', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function batchRescan() {
  const ids = prompt('Enter IDs to rescan (comma-separated):');
  if (!ids) return;
  
  const result = await apiCall('/vulns/batch-rescan', {
    method: 'POST',
    body: { ids: ids.split(',').map(id => id.trim()) }
  });
  
  if (result.success) {
    showNotification('✅ Rescan initiated', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function selectAll() {
  document.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
  showNotification('✅ All items selected', 'info');
}

async function deselectAll() {
  document.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
  showNotification('✅ All items deselected', 'info');
}

// ════════════════════════════════════════════════════════════════
// DATABASE MANAGEMENT BUTTONS
// ════════════════════════════════════════════════════════════════

async function purgeOldData() {
  const days = prompt('Delete records older than (days):', '30');
  if (!days || !confirm('Purge data older than ' + days + ' days?')) return;
  
  const result = await apiCall('/db/purge', {
    method: 'POST',
    body: { days: parseInt(days) }
  });
  
  if (result.success) {
    showNotification('✅ Purged ' + result.data.deleted + ' records', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function clearScanHistory() {
  if (!confirm('Clear all scan history? This cannot be undone!')) return;
  
  const result = await apiCall('/db/clear-history', { method: 'POST' });
  if (result.success) {
    showNotification('✅ Scan history cleared', 'success');
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

async function optimizeDB() {
  const result = await apiCall('/db/optimize', { method: 'POST' });
  if (result.success) {
    showNotification('✅ Database optimized', 'success');
    console.log(result.data);
  } else {
    showNotification('❌ Error: ' + result.error, 'error');
  }
}

// ════════════════════════════════════════════════════════════════
// UPDATE & EXIT HANDLERS
// ════════════════════════════════════════════════════════════════

async function checkForUpdates() {
  showNotification('🔄 Checking for updates...', 'info');
  try {
    const response = await fetch('https://api.github.com/repos/mohidqx/VulnScopeX/releases/latest', {
      headers: { 'Accept': 'application/vnd.github.v3+json' }
    });
    
    if (response.ok) {
      const data = await response.json();
      showNotification(`✅ Latest: ${data.tag_name} | ${data.name}`, 'success');
      console.log('Update Info:', data);
      console.log('Download: ' + data.html_url);
    } else {
      showNotification('Visit: github.com/mohidqx/VulnScopeX for updates', 'info');
    }
  } catch (error) {
    showNotification('⚠️ Could not check updates. Check github.com/mohidqx/VulnScopeX', 'warning');
  }
}

function exitApplication() {
  const confirmed = confirm('❌ Exit SHODAN VulnScopeX?\n\nAny ongoing scans will be stopped.');
  if (confirmed) {
    showNotification('Thanks for using SHODAN VulnScopeX! github.com/mohidqx/VulnScopeX', 'info');
    setTimeout(() => {
      window.location.href = 'about:blank';
      // For server-side exit
      fetch('/api/v2/shutdown', { method: 'POST' }).catch(() => {});
    }, 1500);
  }
}

// ════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS FOR RESULT DISPLAY
// ════════════════════════════════════════════════════════════════

function displayResults(elementId, data, title = 'Results') {
  let html = `<h4>${title}</h4>`;
  
  if (!data || data.length === 0) {
    html += '<p>No results found</p>';
  } else if (typeof data[0] === 'object') {
    html += '<table class="results-table"><thead><tr>';
    const keys = Object.keys(data[0]);
    keys.forEach(key => html += `<th>${key}</th>`);
    html += '</tr></thead><tbody>';
    data.forEach(row => {
      html += '<tr>';
      Object.values(row).forEach(val => html += `<td>${val}</td>`);
      html += '</tr>';
    });
    html += '</tbody></table>';
  } else {
    html += '<ul>' + data.map(item => `<li>${item}</li>`).join('') + '</ul>';
  }
  
  const element = document.getElementById(elementId) || document.querySelector('#dashboardContent');
  if (element) {
    element.innerHTML = html;
    scrollToElement(element, 100);
  }
}

function downloadFile(content, filename, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  window.URL.revokeObjectURL(url);
}

function toggleSection(element) {
  const section = element.nextElementSibling;
  if (section && section.classList.contains('control-section-body')) {
    section.style.display = section.style.display === 'none' ? 'block' : 'none';
  }
}

// ==========================================
// INITIALIZATION
// ==========================================

// Initialize theme when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new ThemeManager();
  initTooltips();
  
  // Initialize main scan button
  const startScanBtn = document.getElementById('startScanBtn');
  if (startScanBtn) {
    startScanBtn.addEventListener('click', async () => {
      const queries = document.getElementById('queriesInput')?.value;
      if (!queries) {
        showNotification('⚠️ Enter queries first', 'warning');
        return;
      }
      
      const result = await apiCall('/scan/start', {
        method: 'POST',
        body: { queries: queries.split('\n').filter(q => q.trim()) }
      });
      
      if (result.success) {
        showNotification('✅ Scan started', 'success');
      } else {
        showNotification('❌ Error: ' + result.error, 'error');
      }
    });
  }
  
  // Initialize load queries button
  const loadQueriesBtn = document.getElementById('loadQueriesBtn');
  if (loadQueriesBtn) {
    loadQueriesBtn.addEventListener('click', loadQueries);
  }
  
  // Initialize update button
  const updateBtn = document.getElementById('updateBtn');
  if (updateBtn) {
    updateBtn.addEventListener('click', checkForUpdates);
  }
  
  // Initialize exit button
  const exitBtn = document.getElementById('exitBtn');
  if (exitBtn) {
    exitBtn.addEventListener('click', exitApplication);
  }
  
  // ════════════════════════════════════════════════════════════════
  // KEYBOARD SHORTCUTS
  // ════════════════════════════════════════════════════════════════
  
  // CTRL+C = Cancel (stop scan)
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
      e.preventDefault();
      showNotification('⏹️ Scan cancelled', 'warning');
      stopScan();
    }
  });
  
  // ESC = Exit
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      const modal = document.querySelector('.modal[style*="display: block"]');
      if (modal) {
        modal.style.display = 'none';
      } else {
        // Show exit confirmation
        const exitConfirm = confirm('Exit SHODAN VulnScopeX? (Press ESC again to confirm)');
        if (exitConfirm) {
          exitApplication();
        }
      }
    }
  });
  
  // GitHub link shortcut (CTRL+G)
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
      e.preventDefault();
      window.open('https://github.com/mohidqx/VulnScopeX', '_blank');
      showNotification('Opening GitHub repository...', 'info');
    }
  });
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ThemeManager,
    formatBytes,
    formatDate,
    getSeverityColor,
    getSeverityLabel,
    copyToClipboard,
    showNotification,
    debounce,
    throttle,
    apiCall,
    isValidEmail,
    isValidUrl,
    generateId,
    parseCSV,
    exportToCSV,
    exportToJSON,
    sortBy,
    filterBy,
    getUnique,
    makeTableClickable,
    initTooltips,
    showLoading,
    confirmDialog,
    startCountdown,
    formatPhone,
    highlightText,
    getBrowserInfo,
    isInViewport,
    scrollToElement
  };
}
