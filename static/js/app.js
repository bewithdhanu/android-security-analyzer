// Global utility functions
window.AppUtils = {
    showLoading() {
        document.getElementById('loading-overlay').classList.remove('hidden');
    },
    
    hideLoading() {
        document.getElementById('loading-overlay').classList.add('hidden');
    },
    
    showFlash(type, message) {
        const container = document.getElementById('flash-container');
        const flash = document.createElement('div');
        flash.className = `flash-${type} border-l-4 p-3 rounded shadow-lg max-w-md`;
        flash.innerHTML = `
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-2">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-triangle' : 'info-circle'} text-sm"></i>
                    <span class="text-sm font-medium">${message}</span>
                </div>
                <button onclick="this.parentElement.parentElement.remove()" class="text-sm opacity-60 hover:opacity-100">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        container.appendChild(flash);
        
        setTimeout(() => {
            if (flash.parentElement) flash.remove();
        }, 5000);
    },
    
    async apiRequest(url, options = {}) {
        try {
            const response = await fetch(url, {
                headers: { 'Content-Type': 'application/json' },
                ...options
            });
            
            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.detail || `HTTP ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            this.showFlash('error', error.message);
            throw error;
        }
    },
    
    toggleElement(id) {
        const element = document.getElementById(id);
        const icon = element.previousElementSibling.querySelector('.expand-icon');
        
        element.classList.toggle('hidden');
        icon.classList.toggle('expanded');
    },
    
    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    },
    
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // File Upload Utilities
    formatFileSize(bytes) {
        if (bytes > 1024 * 1024 * 1024) {
            return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
        } else if (bytes > 1024 * 1024) {
            return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
        } else if (bytes > 1024) {
            return `${(bytes / 1024).toFixed(2)} KB`;
        }
        return `${bytes} bytes`;
    },

    validateFileSize(file, maxSize = 1024 * 1024 * 1024) { // Default 1GB
        if (file.size > maxSize) {
            this.showFlash('error', `File size exceeds ${this.formatFileSize(maxSize)} limit`);
            return false;
        }
        return true;
    },

    validateFileType(file, allowedTypes = ['application/zip']) {
        if (!allowedTypes.includes(file.type)) {
            this.showFlash('error', 'Invalid file type. Please upload a ZIP file.');
            return false;
        }
        return true;
    }
};

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide flash messages
    document.querySelectorAll('[class*="flash-"]').forEach(flash => {
        setTimeout(() => flash.remove(), 5000);
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-backdrop').forEach(modal => {
                modal.classList.add('hidden');
            });
        }
    });
}); 