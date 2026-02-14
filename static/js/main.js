// Kiratu's Shoes – Main JavaScript

// ── Theme Toggle ──
function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'light' ? 'dark' : 'light';
    window.location.href = '/set-theme/' + next;
}

// ── Mobile Menu ──
function toggleMobileMenu() {
    const menu = document.getElementById('mobileMenu');
    if (menu) menu.classList.toggle('open');
}

// ── Auto-dismiss flash messages ──
document.addEventListener('DOMContentLoaded', function () {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(function (f) {
        setTimeout(function () {
            f.style.opacity = '0';
            f.style.transform = 'translateX(100%)';
            f.style.transition = 'all 0.4s ease';
            setTimeout(() => f.remove(), 400);
        }, 5000);
    });
});

// ── Password Strength Checker ──
function checkPasswordStrength(password) {
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const len = password.length;
    if (len < 8) return 'weak';
    const score = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    if (score <= 2) return 'weak';
    if (score === 3) return 'medium';
    return 'strong';
}

function updateStrengthMeter(inputId, meterId) {
    const input = document.getElementById(inputId);
    const meter = document.getElementById(meterId);
    if (!input || !meter) return;
    input.addEventListener('input', function () {
        const strength = checkPasswordStrength(this.value);
        meter.className = 'strength-meter strength-' + strength;
        const label = meter.querySelector('.strength-label');
        if (label) label.textContent = strength.charAt(0).toUpperCase() + strength.slice(1);
    });
}

// ── File Upload Preview ──
function initFilePreview(inputId, previewId) {
    const input = document.getElementById(inputId);
    const preview = document.getElementById(previewId);
    if (!input || !preview) return;
    input.addEventListener('change', function () {
        const file = this.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function (e) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        }
    });
}

// ── Confirm Delete ──
function confirmDelete(message) {
    return confirm(message || 'Are you sure you want to delete this? This cannot be undone.');
}

// ── Form Validation Helper ──
function validateRequiredFields(formId) {
    const form = document.getElementById(formId);
    if (!form) return true;
    const inputs = form.querySelectorAll('[required]');
    let valid = true;
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.style.borderColor = 'var(--danger)';
            valid = false;
        } else {
            input.style.borderColor = '';
        }
    });
    return valid;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
    // Password strength on register/change-password pages
    updateStrengthMeter('password', 'strengthMeter');
    updateStrengthMeter('new_password', 'strengthMeter');

    // File upload preview
    initFilePreview('imageInput', 'imagePreview');

    // File drag-over
    const uploadArea = document.querySelector('.file-upload-area');
    if (uploadArea) {
        uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.style.borderColor = 'var(--gold)'; });
        uploadArea.addEventListener('dragleave', () => { uploadArea.style.borderColor = ''; });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '';
            const fileInput = uploadArea.querySelector('input[type=file]');
            if (fileInput && e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                fileInput.dispatchEvent(new Event('change'));
            }
        });
    }
});
