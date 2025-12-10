// Authentication page JavaScript
(function() {
  const API_BASE = window.location.origin;
  
  function byId(id) { return document.getElementById(id); }
  function qs(sel, root = document) { return root.querySelector(sel); }
  
  // Tab switching
  function initTabs() {
    const tabs = document.querySelectorAll('.auth-tab');
    const forms = document.querySelectorAll('.auth-form');
    
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        
        // Update tabs
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Update forms
        forms.forEach(form => {
          form.classList.remove('active');
          if (form.id === `${targetTab}-form`) {
            form.classList.add('active');
          }
        });
      });
    });
  }
  
  // Form validation
  function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }
  
  function validatePassword(password) {
    return password.length >= 6;
  }
  
  // Show error/success messages
  function showError(formId, message) {
    const errorEl = byId(`${formId}-error`);
    const successEl = byId(`${formId}-success`);
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }
    if (successEl) {
      successEl.style.display = 'none';
    }
  }
  
  function showSuccess(formId, message) {
    const errorEl = byId(`${formId}-error`);
    const successEl = byId(`${formId}-success`);
    if (successEl) {
      successEl.textContent = message;
      successEl.style.display = 'block';
    }
    if (errorEl) {
      errorEl.style.display = 'none';
    }
  }
  
  function clearMessages(formId) {
    const errorEl = byId(`${formId}-error`);
    const successEl = byId(`${formId}-success`);
    if (errorEl) errorEl.style.display = 'none';
    if (successEl) successEl.style.display = 'none';
  }
  
  // Login handler
  async function handleLogin(e) {
    e.preventDefault();
    clearMessages('login');
    
    const email = byId('login-email').value.trim();
    const password = byId('login-password').value;
    
    if (!validateEmail(email)) {
      showError('login', 'Please enter a valid email address');
      return;
    }
    
    if (!password) {
      showError('login', 'Please enter your password');
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      });
      
      const result = await response.json();
      
      if (!response.ok || !result.success) {
        showError('login', result.message || 'Login failed. Please check your credentials.');
        return;
      }
      
      showSuccess('login', 'Login successful! Redirecting...');
      setTimeout(() => {
        window.location.href = '/index.html';
      }, 1500);
      
    } catch (error) {
      showError('login', 'Network error. Please try again.');
    }
  }
  
  // Signup handler
  async function handleSignup(e) {
    e.preventDefault();
    clearMessages('signup');
    
    const name = byId('signup-name').value.trim();
    const email = byId('signup-email').value.trim();
    const password = byId('signup-password').value;
    const confirm = byId('signup-confirm').value;
    
    if (!validateEmail(email)) {
      showError('signup', 'Please enter a valid email address');
      return;
    }
    
    if (!validatePassword(password)) {
      showError('signup', 'Password must be at least 6 characters long');
      return;
    }
    
    if (password !== confirm) {
      showError('signup', 'Passwords do not match');
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/api/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password, name })
      });
      
      const result = await response.json();
      
      if (!response.ok || !result.success) {
        showError('signup', result.message || 'Registration failed. Please try again.');
        return;
      }
      
      showSuccess('signup', 'Registration successful! Please check your email to verify your account.');
      
      // Clear form
      byId('signup-form').reset();
      
      // Switch to login tab after 2 seconds
      setTimeout(() => {
        qs('.auth-tab[data-tab="login"]').click();
      }, 2000);
      
    } catch (error) {
      showError('signup', 'Network error. Please try again.');
    }
  }
  
  // Forgot password handler
  async function handleForgotPassword(e) {
    e.preventDefault();
    
    const email = prompt('Enter your email address:');
    if (!email || !validateEmail(email)) {
      alert('Please enter a valid email address');
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/api/password/forgot`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });
      
      const result = await response.json();
      
      if (response.ok && result.success) {
        alert('If an account with that email exists, you will receive a password reset link.');
      } else {
        alert('Failed to send reset link. Please try again.');
      }
      
    } catch (error) {
      alert('Network error. Please try again.');
    }
  }
  
  // Initialize
  function init() {
    initTabs();
    
    // Form submissions
    byId('login-form').addEventListener('submit', handleLogin);
    byId('signup-form').addEventListener('submit', handleSignup);
    
    // Forgot password link
    byId('forgot-password').addEventListener('click', handleForgotPassword);
    
    // Switch to login link
    byId('switch-to-login').addEventListener('click', (e) => {
      e.preventDefault();
      qs('.auth-tab[data-tab="login"]').click();
    });
  }
  
  // Start when DOM is ready
  document.addEventListener('DOMContentLoaded', init);
})();
