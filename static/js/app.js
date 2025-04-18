/**
 * Network Threat Analyzer - Main JavaScript File
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Handle file upload form
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function(e) {
            const fileInput = document.getElementById('file');
            
            if (!fileInput.files.length) {
                e.preventDefault();
                alert('Please select a file to upload');
                return false;
            }
            
            const file = fileInput.files[0];
            const fileType = file.name.split('.').pop().toLowerCase();
            
            // Check file type
            if (!['pcap', 'pcapng', 'cap'].includes(fileType)) {
                e.preventDefault();
                alert('Invalid file type. Please upload a PCAP file (.pcap, .pcapng, .cap)');
                return false;
            }
            
            // Check file size (max 50MB)
            if (file.size > 50 * 1024 * 1024) {
                e.preventDefault();
                alert('File is too large. Maximum size is 50MB');
                return false;
            }
            
            // Show loading state
            const submitBtn = document.getElementById('submit-btn');
            if (submitBtn) {
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';
                submitBtn.disabled = true;
            }
            
            return true;
        });
    }
    
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert-dismissible');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

/**
 * Format bytes to human-readable format
 * @param {number} bytes - Number of bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
