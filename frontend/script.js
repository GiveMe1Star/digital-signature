/**
 * Digital Signature System - Frontend
 * Tương tác với API backend
 */

const API_BASE = 'http://localhost:8000';

// ==================== STATE ====================
const state = {
    signFile: null,
    privateKey: null,
    verifyFile: null,
    signature: null,
    directory: []
};

// ==================== DOM ELEMENTS ====================
const elements = {
    // Sign
    signFileZone: document.getElementById('signFileZone'),
    signFileInput: document.getElementById('signFileInput'),
    signFileInfo: document.getElementById('signFileInfo'),
    signFileName: document.getElementById('signFileName'),
    privateKeyZone: document.getElementById('privateKeyZone'),
    privateKeyInput: document.getElementById('privateKeyInput'),
    privateKeyInfo: document.getElementById('privateKeyInfo'),
    privateKeyName: document.getElementById('privateKeyName'),
    signBtn: document.getElementById('signBtn'),
    signResult: document.getElementById('signResult'),
    
    // Verify
    verifyFileZone: document.getElementById('verifyFileZone'),
    verifyFileInput: document.getElementById('verifyFileInput'),
    verifyFileInfo: document.getElementById('verifyFileInfo'),
    verifyFileName: document.getElementById('verifyFileName'),
    signatureZone: document.getElementById('signatureZone'),
    signatureInput: document.getElementById('signatureInput'),
    signatureInfo: document.getElementById('signatureInfo'),
    signatureName: document.getElementById('signatureName'),
    signerSelect: document.getElementById('signerSelect'),
    verifyBtn: document.getElementById('verifyBtn'),
    verifyResult: document.getElementById('verifyResult'),
    
    // Generate
    generateForm: document.getElementById('generateForm'),
    generateResult: document.getElementById('generateResult'),
    
    // Directory
    directoryTable: document.getElementById('directoryTable'),
    registerForm: document.getElementById('registerForm'),
    
    // UI
    loadingSpinner: document.getElementById('loadingSpinner'),
    mainNav: document.getElementById('mainNav')
};

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    initDropZones();
    initNavigation();
    initForms();
    loadDirectory();
});

// ==================== NAVIGATION ====================
function initNavigation() {
    elements.mainNav.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = link.dataset.tab;
            
            // Update active
            elements.mainNav.querySelectorAll('.nav-link').forEach(l => 
                l.classList.remove('active'));
            link.classList.add('active');
            
            // Show/hide tabs
            document.querySelectorAll('.tab-content').forEach(tab => 
                tab.classList.add('d-none'));
            document.getElementById(`${tabId}-tab`).classList.remove('d-none');
            
            // Refresh directory
            if (tabId === 'directory') {
                loadDirectory();
            }
        });
    });
}

// ==================== DROP ZONES ====================
function initDropZones() {
    const zones = [
        { zone: elements.signFileZone, input: elements.signFileInput, handler: handleSignFile },
        { zone: elements.privateKeyZone, input: elements.privateKeyInput, handler: handlePrivateKey },
        { zone: elements.verifyFileZone, input: elements.verifyFileInput, handler: handleVerifyFile },
        { zone: elements.signatureZone, input: elements.signatureInput, handler: handleSignature }
    ];
    
    zones.forEach(({ zone, input, handler }) => {
        zone.addEventListener('click', () => input.click());
        
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });
        
        zone.addEventListener('dragleave', () => {
            zone.classList.remove('dragover');
        });
        
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
            if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]);
        });
        
        input.addEventListener('change', () => {
            if (input.files[0]) handler(input.files[0]);
        });
    });
}

function handleSignFile(file) {
    state.signFile = file;
    elements.signFileZone.classList.add('has-file');
    elements.signFileName.textContent = file.name;
    elements.signFileInfo.classList.add('show');
    updateSignButton();
}

function handlePrivateKey(file) {
    state.privateKey = file;
    elements.privateKeyZone.classList.add('has-file');
    elements.privateKeyName.textContent = file.name;
    elements.privateKeyInfo.classList.add('show');
    updateSignButton();
}

function handleVerifyFile(file) {
    state.verifyFile = file;
    elements.verifyFileZone.classList.add('has-file');
    elements.verifyFileName.textContent = file.name;
    elements.verifyFileInfo.classList.add('show');
    updateVerifyButton();
}

function handleSignature(file) {
    state.signature = file;
    elements.signatureZone.classList.add('has-file');
    elements.signatureName.textContent = file.name;
    elements.signatureInfo.classList.add('show');
    updateVerifyButton();
}

function updateSignButton() {
    elements.signBtn.disabled = !(state.signFile && state.privateKey);
}

function updateVerifyButton() {
    const hasAll = state.verifyFile && state.signature && elements.signerSelect.value;
    elements.verifyBtn.disabled = !hasAll;
}

// ==================== FORMS ====================
function initForms() {
    elements.signBtn.addEventListener('click', signDocument);
    elements.verifyBtn.addEventListener('click', verifyDocument);
    elements.signerSelect.addEventListener('change', updateVerifyButton);
    elements.generateForm.addEventListener('submit', generateKeys);
    elements.registerForm.addEventListener('submit', registerKey);
}

// ==================== API CALLS ====================
async function signDocument() {
    showLoading(true);
    hideResult(elements.signResult);
    
    try {
        const formData = new FormData();
        formData.append('file', state.signFile);
        formData.append('private_key', state.privateKey);
        
        const response = await fetch(`${API_BASE}/sign`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Signing failed');
        }
        
        // Download signature
        const blob = await response.blob();
        downloadFile(blob, `${state.signFile.name}.sig`);
        
        showResult(elements.signResult, true, 
            `<i class="bi bi-check-circle me-2"></i>Ký thành công! File chữ ký đã tải về.`);
        
    } catch (error) {
        showResult(elements.signResult, false, 
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function verifyDocument() {
    showLoading(true);
    hideResult(elements.verifyResult);
    
    try {
        const formData = new FormData();
        formData.append('file', state.verifyFile);
        formData.append('signature', state.signature);
        formData.append('key_id', elements.signerSelect.value);
        
        const response = await fetch(`${API_BASE}/verify`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Verification failed');
        }
        
        const result = await response.json();
        
        if (result.valid) {
            showResult(elements.verifyResult, true,
                `<i class="bi bi-shield-check me-2"></i>${result.message}<br>
                <small class="mt-2 d-block">Người ký: <strong>${result.signer}</strong></small>`);
        } else {
            showResult(elements.verifyResult, false,
                `<i class="bi bi-shield-x me-2"></i>${result.message}`);
        }
        
    } catch (error) {
        showResult(elements.verifyResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function generateKeys(e) {
    e.preventDefault();
    showLoading(true);
    hideResult(elements.generateResult);
    
    const name = document.getElementById('genName').value;
    const department = document.getElementById('genDepartment').value;
    const keySize = document.getElementById('genKeySize').value;
    
    try {
        const formData = new FormData();
        formData.append('name', name);
        formData.append('department', department);
        formData.append('key_size', keySize);
        
        const response = await fetch(`${API_BASE}/generate-keys`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Generation failed');
        }
        
        const keyId = response.headers.get('X-Key-ID');
        const blob = await response.blob();
        downloadFile(blob, `${name.replace(/\s+/g, '_')}_private.key`);
        
        showResult(elements.generateResult, true,
            `<i class="bi bi-check-circle me-2"></i>Sinh khóa thành công!<br>
            <small class="mt-2 d-block">Key ID: <strong>${keyId}</strong></small>
            <small>Private key đã tải về. Public key đã được đăng ký.</small>`);
        
        elements.generateForm.reset();
        loadDirectory();
        
    } catch (error) {
        showResult(elements.generateResult, false,
            `<i class="bi bi-exclamation-circle me-2"></i>${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function registerKey(e) {
    e.preventDefault();
    showLoading(true);
    
    const name = document.getElementById('regName').value;
    const department = document.getElementById('regDepartment').value;
    const publicKey = document.getElementById('regPublicKey').files[0];
    
    try {
        const formData = new FormData();
        formData.append('name', name);
        formData.append('department', department);
        formData.append('public_key', publicKey);
        
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Registration failed');
        }
        
        bootstrap.Modal.getInstance(document.getElementById('registerModal')).hide();
        elements.registerForm.reset();
        loadDirectory();
        
    } catch (error) {
        alert(`Lỗi: ${error.message}`);
    } finally {
        showLoading(false);
    }
}

async function loadDirectory() {
    try {
        const response = await fetch(`${API_BASE}/directory`);
        if (!response.ok) throw new Error('Failed to load');
        
        const data = await response.json();
        state.directory = data.entries || [];
        renderDirectory();
        updateSignerSelect();
        
    } catch (error) {
        console.error('Load directory failed:', error);
        state.directory = [];
        renderDirectory();
    }
}

async function deleteKey(keyId) {
    if (!confirm('Xác nhận xóa khóa này?')) return;
    
    showLoading(true);
    try {
        const response = await fetch(`${API_BASE}/directory/${keyId}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) throw new Error('Delete failed');
        loadDirectory();
        
    } catch (error) {
        alert(`Lỗi: ${error.message}`);
    } finally {
        showLoading(false);
    }
}

// ==================== UI HELPERS ====================
function renderDirectory() {
    if (state.directory.length === 0) {
        elements.directoryTable.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted py-4">
                    <i class="bi bi-inbox fs-1 d-block mb-2"></i>
                    Chưa có khóa nào được đăng ký
                </td>
            </tr>`;
        return;
    }
    
    elements.directoryTable.innerHTML = state.directory.map(entry => `
        <tr>
            <td><span class="key-badge">${escapeHtml(entry.id)}</span></td>
            <td><strong>${escapeHtml(entry.name)}</strong></td>
            <td>${escapeHtml(entry.department)}</td>
            <td>${formatDate(entry.created_at)}</td>
            <td>
                <button class="btn btn-sm btn-outline-danger" 
                        onclick="deleteKey('${entry.id}')">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function updateSignerSelect() {
    elements.signerSelect.innerHTML = '<option value="">-- Chọn người ký --</option>';
    state.directory.forEach(entry => {
        const option = document.createElement('option');
        option.value = entry.id;
        option.textContent = `${entry.name} (${entry.department})`;
        elements.signerSelect.appendChild(option);
    });
}

function showResult(element, success, message) {
    element.className = `result-alert show ${success ? 'success' : 'error'}`;
    element.innerHTML = message;
}

function hideResult(element) {
    element.classList.remove('show');
}

function showLoading(show) {
    elements.loadingSpinner.classList.toggle('show', show);
}

function downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(isoString) {
    try {
        const date = new Date(isoString);
        return date.toLocaleString('vi-VN');
    } catch {
        return isoString;
    }
}

// Expose to global
window.deleteKey = deleteKey;
