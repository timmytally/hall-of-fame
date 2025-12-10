// Password reset page JavaScript
(function() {
  const API_BASE = window.location.origin;
  
  function byId(id) { return document.getElementById(id); }
  
  // Get URL parameters
  function getUrlParam(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
  }
  
  // Form validation
  function validatePassword(password) {
    return password.length >= 6;
  }
  
  // Show error/success messages
  function showError(message) {
    const errorEl = byId('reset-error');
    const successEl = byId('reset-success');
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }
    if (successEl) {
      successEl.style.display = 'none';
    }
  }
  
  function showSuccess(message) {
    const errorEl = byId('reset-error');
    const successEl = byId('reset-success');
    if (successEl) {
      successEl.textContent = message;
      successEl.style.display = 'block';
    }
    if (errorEl) {
      errorEl.style.display = 'none';
    }
  }
  
  function clearMessages() {
    const errorEl = byId('reset-error');
    const successEl = byId('reset-success');
    if (errorEl) errorEl.style.display = 'none';
    if (successEl) successEl.style.display = 'none';
  }
  
  // Reset password handler
  async function handleReset(e) {
    e.preventDefault();
    clearMessages();
    
    const token = byId('token').value;
    const email = byId('email').value;
    const password = byId('password').value;
    const confirm = byId('confirm').value;
    
    if (!validatePassword(password)) {
      showError('Password must be at least 6 characters long');
      return;
    }
    
    if (password !== confirm) {
      showError('Passwords do not match');
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/api/password/reset`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token, email, password })
      });
      
      const result = await response.json();
      
      if (!response.ok || !result.success) {
        showError(result.message || 'Failed to reset password. The link may have expired.');
        return;
      }
      
      showSuccess('Password reset successful! Redirecting to login...');
      
      // Clear form
      byId('reset-form').reset();
      
      // Redirect to login after 2 seconds
      setTimeout(() => {
        window.location.href = 'auth.html';
      }, 2000);
      
    } catch (error) {
      showError('Network error. Please try again.');
    }
  }
  
  // Initialize
  function init() {
    // Get token and email from URL
    const token = getUrlParam('token');
    const email = getUrlParam('email');
    
    if (!token || !email) {
      showError('Invalid or expired reset link');
      return;
    }
    
    // Set hidden fields
    byId('token').value = token;
    byId('email').value = email;
    
    // Form submission
    byId('reset-form').addEventListener('submit', handleReset);
  }
  
  // Start when DOM is ready
  document.addEventListener('DOMContentLoaded', init);
})();
