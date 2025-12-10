// Single IIFE - app bootstrap and handlers
(function(){
  const STORAGE_KEY = 'hof_winners_v1';
  const THEME_KEY = 'hof_theme_v1';
  const ADMIN_HASH_KEY = 'hof_admin_hash_v1';
  const ADMIN_PASSWORD_FALLBACK = 'admin123'; // legacy fallback

  function byId(id){return document.getElementById(id)}
  function qs(sel, root=document){return root.querySelector(sel)}

  // Utilities
  function loadData(){
    try {return JSON.parse(localStorage.getItem(STORAGE_KEY)||'null')||[];}catch(e){return []}
  }

  // Backend data loader (always use API for consistent data)
  async function loadBackendData(){
    try {
      const r = await fetch('/api/winners');
      if (!r.ok) return [];
      return await r.json();
    } catch(e) {
      console.error('Failed to load backend data:', e);
      return [];
    }
  }

  // Public data loader for shareable links
  async function loadPublicData(){
    try {
      return await apiGetPublicWinners();
    } catch(e) {
      console.error('Failed to load public winners:', e);
      return [];
    }
  }
  function saveData(arr){localStorage.setItem(STORAGE_KEY, JSON.stringify(arr))}

  // Seed samples if empty
  function ensureSeed(){
    let arr = loadData();
    if(arr.length===0){
      arr = [
        {id:cryptoId(),name:'PESSI',wa:'+254',title:'Summer Cup',rank:1,score:'3-1',date:'2025-11-22',photo:null,createdAt:Date.now()},
        {id:cryptoId(),name:'TIMMY',wa:'+254',title:'Autumn Clash',rank:2,score:'2-3',date:'2025-10-05',photo:null,createdAt:Date.now()-86400000*10}
      ];
      saveData(arr);
    }
  }
  function cryptoId(){return Math.random().toString(36).slice(2,10)}

  // Theme handling
  function initTheme(){
    const saved = localStorage.getItem(THEME_KEY) || (window.matchMedia && window.matchMedia('(prefers-color-scheme:light)').matches ? 'light' : 'dark');
    setTheme(saved);
    document.querySelectorAll('#theme-toggle').forEach(btn=>btn.addEventListener('click',()=>{
      const next = document.documentElement.classList.contains('light') ? 'dark' : 'light';
      setTheme(next);
    }))
  }
  function setTheme(t){
    if(t==='light') document.documentElement.classList.add('light');
    else document.documentElement.classList.remove('light');
    localStorage.setItem(THEME_KEY, t);
    document.querySelectorAll('#theme-toggle').forEach(btn=>{
      btn.textContent = t==='light' ? '🌞' : '🌙';
      btn.setAttribute('aria-label', t==='light' ? 'Switch to dark theme' : 'Switch to light theme');
    });
  }

  // Page-specific boot
  function boot(){
    initTheme();
    const page = document.body.dataset.page;
    if (page === 'home') {
      initHome();
    } else if (page === 'winners') {
      initWinners();
    } else if (page === 'admin') {
      initAdmin();
    }
  }

  // Home page
  function initHome(){
    ensureSeed();
    // Update stats (async)
    updateHomeStats();
    // Initialize settings button
    initSettingsButton();
    // Initialize settings modal
    initSettingsModal();
    // Profile will be handled by loadAndShowProfile
    loadAndShowProfile();
  }

  function initSettingsButton(){
    const settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn && !settingsBtn.dataset.wired) {
      settingsBtn.addEventListener('click', () => {
        const modal = document.getElementById('settings-modal');
        if (modal) {
          modal.style.display = 'flex';
        }
      });
      settingsBtn.dataset.wired = '1';
    }
  }

  function initSettingsModal(){
    const modal = document.getElementById('settings-modal');
    const closeBtn = modal?.querySelector('.modal-close');
    const profileView = document.getElementById('profile-view');
    const profileEdit = document.getElementById('profile-edit');
    const profileEditBtn = document.getElementById('profile-edit-btn');
    const profileCancelBtn = document.getElementById('profile-cancel-btn');
    const profileForm = document.getElementById('profile-form');

    // Close modal handlers
    if (closeBtn && !closeBtn.dataset.wired) {
      closeBtn.addEventListener('click', () => {
        if (modal) modal.style.display = 'none';
      });
      closeBtn.dataset.wired = '1';
    }

    if (modal && !modal.dataset.wired) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
      modal.dataset.wired = '1';
    }

    // Profile edit handlers
    if (profileEditBtn && !profileEditBtn.dataset.wired) {
      profileEditBtn.addEventListener('click', () => {
        const prof = getCurrentProfile();
        if (profileForm) {
          profileForm.elements['name'].value = prof.name || '';
        }
        if (profileView) profileView.style.display = 'none';
        if (profileEdit) profileEdit.style.display = 'block';
      });
      profileEditBtn.dataset.wired = '1';
    }

    if (profileCancelBtn && !profileCancelBtn.dataset.wired) {
      profileCancelBtn.addEventListener('click', () => {
        if (profileView) profileView.style.display = 'block';
        if (profileEdit) profileEdit.style.display = 'none';
      });
      profileCancelBtn.dataset.wired = '1';
    }

    // Profile form submission
    if (profileForm && !profileForm.dataset.wired) {
      profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(profileForm);
        const name = formData.get('name')?.trim() || '';
        const avatarFile = formData.get('avatar');
        
        try {
          let response;
          if (avatarFile && avatarFile.size > 0) {
            const uploadFormData = new FormData();
            uploadFormData.append('name', name);
            uploadFormData.append('avatar', avatarFile);
            
            response = await fetch('/api/profile', {
              method: 'PUT',
              credentials: 'include',
              body: uploadFormData
            });
          } else {
            const payload = { name };
            response = await fetch('/api/profile', {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify(payload)
            });
          }
          
          if (!response.ok) throw new Error('Update failed');
          const result = await response.json();
          alert('Profile updated.');
          
          // Update display
          if (profileView) profileView.style.display = 'block';
          if (profileEdit) profileEdit.style.display = 'none';
          
          // Reload profile data
          if (result.profile) {
            await loadAndShowProfileWithProfile(result.profile);
          } else {
            await loadAndShowProfile();
          }
        } catch (err) {
          alert('Failed to update profile.');
        }
      });
      profileForm.dataset.wired = '1';
    }

    // Logout button in settings
    const profileLogout = document.getElementById('profile-logout');
    if (profileLogout && !profileLogout.dataset.wired) {
      profileLogout.addEventListener('click', async () => {
        try {
          await fetch('/api/logout', { credentials: 'include' });
          document.cookie = 'user_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
          window.location.href = 'index.html';
        } catch (e) {
          console.error('Logout error:', e);
          window.location.href = 'index.html';
        }
      });
      profileLogout.dataset.wired = '1';
    }
  }

  function getCurrentProfile(){
    // Try to get current profile from nav elements
    const navName = document.getElementById('nav-name');
    const navAvatar = document.getElementById('nav-avatar');
    const navProfile = document.getElementById('nav-profile');
    
    if (navProfile && navProfile.style.display !== 'none') {
      return {
        name: navName?.textContent || '',
        picture: navAvatar?.src || ''
      };
    }
    return { name: '', picture: '' };
  }

  function updateSettingsModal(prof){
    const settingsName = document.getElementById('settings-name');
    const settingsEmail = document.getElementById('settings-email');
    const settingsAvatar = document.getElementById('settings-avatar');
    
    if (settingsName) settingsName.textContent = prof.name || prof.email || 'Profile';
    if (settingsEmail) settingsEmail.textContent = prof.email || '';
    if (settingsAvatar) settingsAvatar.src = prof.picture && !prof.picture.includes('googleusercontent.com') && !prof.picture.includes('efootball') ? prof.picture : 'images/profile.svg';
  }

  async function updateHomeStats(){
    const data = await loadBackendData();
    const winnersCount = data.length;
    const tournamentsCount = [...new Set(data.map(w=>w.title).filter(Boolean))].length;
    const playersCount = [...new Set(data.map(w=>w.name).filter(Boolean))].length;
    
    // Update stat numbers
    const statWinners = document.getElementById('stat-winners');
    const statTournaments = document.getElementById('stat-tournaments');
    const statPlayers = document.getElementById('stat-players');
    
    if (statWinners) statWinners.textContent = winnersCount;
    if (statTournaments) statTournaments.textContent = tournamentsCount;
    if (statPlayers) statPlayers.textContent = playersCount;
    
    // Hide CTA section if winners exist
    const ctaSection = document.getElementById('cta-section');
    if (ctaSection) {
      ctaSection.style.display = winnersCount > 0 ? 'none' : 'block';
    }
  }

  // Winners page
  async function initWinners(){
    const isPublicMode = new URLSearchParams(window.location.search).get('public') === 'true';
    
    // For public mode, don't seed data, just load from API
    if (!isPublicMode) {
      ensureSeed();
    }
    
    const listEl = byId('winners-list');
    const search = byId('search');
    const tournamentFilter = byId('tournament-filter');
    const shareSiteBtn = byId('share-site');
    const tpl = qs('#winner-card-tpl');

    // Populate tournament filter
    const backendData = await loadBackendData();
    const tournaments = [...new Set(backendData.map(w=>w.title).filter(Boolean))];
    if(tournamentFilter){
      tournamentFilter.innerHTML = '<option value="">All Tournaments</option>';
      tournaments.forEach(t=>{
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        tournamentFilter.appendChild(opt);
      })
    }

    async function render(filter, tournamentFilter){
      const isPublicMode = new URLSearchParams(window.location.search).get('public') === 'true';
      let data;
      
      if (isPublicMode) {
        data = await loadPublicData();
      } else {
        data = await loadBackendData();
      }
      
      data = data.slice().sort((a,b)=> new Date(b.date) - new Date(a.date) || (b.createdAt||0)-(a.createdAt||0));
      console.log('render called with data:', data.length, 'winners');
      const q = (filter||'').toLowerCase();
      const t = (tournamentFilter||'').trim();
      const matched = data.filter(it => {
        let qMatch = !q || (it.name||'').toLowerCase().includes(q) || (it.title||'').toLowerCase().includes(q);
        let tMatch = !t || (it.title||'') === t;
        return qMatch && tMatch;
      })
      if(matched.length===0){ listEl.innerHTML='<div class="muted">No winners found. Admins can add winners via the Admin page.</div>'; return }
      matched.forEach(w=>{
        const node = tpl.content.cloneNode(true);
        const card = node.querySelector('.winner-card');
        const img = node.querySelector('.avatar');
        const awardImg = node.querySelector('.award-badge');
        const pname = node.querySelector('.player-name');
        const rankb = node.querySelector('.rank-badge');
        const tournament = node.querySelector('.tournament');
        const scoreDate = node.querySelector('.score-date');
        const shareBtn = node.querySelector('.share-btn');
        
        // Use uploaded photo as avatar
        if(w.photo){
          img.src = w.photo;
        } else {
          img.src = 'data:image/svg+xml;utf8,'+encodeURIComponent(defaultAvatarSvg(w.name));
        }
        img.alt = (w.name||'player')+' photo';
        
        // Get award image and display as badge overlay
        const awardOrPhoto = getRankAwardSvg(w.rank);
        if(awardOrPhoto.startsWith('images/')){
          awardImg.src = awardOrPhoto;
          awardImg.style.display = 'block';
        } else if(awardOrPhoto.startsWith('data:')){
          awardImg.src = awardOrPhoto;
          awardImg.style.display = 'block';
        } else {
          awardImg.src = 'data:image/svg+xml;utf8,'+encodeURIComponent(awardOrPhoto);
          awardImg.style.display = 'block';
        }
        awardImg.alt = 'Rank '+w.rank+' award';
        
        pname.textContent = w.name || 'Unknown';
        rankb.textContent = (w.rank==1? '1st' : w.rank==2? '2nd' : w.rank==3? '3rd' : w.rank);
        tournament.textContent = w.title || '';
        scoreDate.textContent = (w.score? ('Score: '+w.score + ' • ') : '') + formatDate(w.date);
        shareBtn.addEventListener('click', ()=> shareWinner(w));
        listEl.appendChild(node);
      })
    }
    
    render();
    search&&search.addEventListener('input',e=>render(e.target.value, tournamentFilter.value));
    tournamentFilter&&tournamentFilter.addEventListener('change',e=>render(search.value, e.target.value));

    shareSiteBtn&&shareSiteBtn.addEventListener('click', ()=>{
      generateShareableLink();
    })
  }

  function formatDate(d){ if(!d) return ''; try{return new Date(d).toLocaleDateString()}catch(e){return d}}
  
  function getRankAwardSvg(rank){
    const rankNum = parseInt(rank);
    if(rankNum===1){
      // Use custom image for 1st place
      return 'images/winner1.png';
    } else if(rankNum===2){
      // Silver Medal for 2nd place
      return 'images/second.png';
    } else if(rankNum===3){
      // Bronze Medal for 3rd place
      return 'images/3rd.png';
    } else {
      // Default star for other ranks
      return `<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160' viewBox='0 0 100 100'><defs><linearGradient id='starGrad' x1='0' x2='1' y1='0' y2='1'><stop offset='0%' stop-color='%230099ff'/><stop offset='100%' stop-color='%2300ccff'/></linearGradient></defs><circle cx='50' cy='50' r='48' fill='url(%23starGrad)'/><path d='M50 20l12 30h32l-26 20 10 30L50 70 26 85l-26-20 32-30z' fill='%23ffff00'/><circle cx='50' cy='50' r='2' fill='%23fff'/></svg>`;
    }
  }

  function defaultAvatarSvg(name){
    const initials = (name||'?').split(' ').map(x=>x[0]).slice(0,2).join('').toUpperCase();
    return `<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><rect width='100%' height='100%' fill='%23e52e71'/><text x='50%' y='55%' dominant-baseline='middle' text-anchor='middle' font-family='Arial' font-size='48' fill='white'>${initials}</text></svg>`
  }

  function shareWinner(w){
    const url = location.href.replace(/winners\.html.*/,'winners.html');
    const text = `🏆 ${w.name} — ${w.title}\nRank: ${w.rank}\n${w.score?('Score: '+w.score+'\n'):''}Date: ${w.date}\nSee more: ${url}`;
    shareWhatsApp(text);
  }
  function shareWhatsApp(text){
    const encoded = encodeURIComponent(text);
    const wa = `https://wa.me/?text=${encoded}`;
    window.open(wa, '_blank');
  }

  // Generate shareable link for public viewing
  function generateShareableLink(tournament = null, player = null) {
    const baseUrl = window.location.origin + '/winners.html';
    const params = new URLSearchParams();
    
    // Add public mode flag
    params.set('public', 'true');
    
    // Optional filters
    if (tournament) params.set('tournament', tournament);
    if (player) params.set('player', player);
    
    const url = params.toString() ? `${baseUrl}?${params.toString()}` : baseUrl;
    
    // Copy to clipboard and show message
    navigator.clipboard.writeText(url).then(() => {
      alert('Shareable link copied to clipboard!\n\n' + url);
    }).catch(() => {
      prompt('Shareable link (copy this):', url);
    });
    
    return url;
  }

  // API helpers
  async function apiProfileGet(){
    const r = await fetch('/api/me', { credentials: 'include' });
    if (!r.ok) throw new Error('Not logged in');
    const d = await r.json();
    return d.user || null;
  }

  // Public API for winners (no authentication required)
  async function apiGetPublicWinners(){
    const r = await fetch('/public/winners');
    if (!r.ok) throw new Error('Failed to load winners');
    const d = await r.json();
    return d.winners || [];
  }

  // Admin page logic with first-time setup (stores a hashed password in localStorage)
  async function hashPassword(pw){
    try{
      if(window.crypto && crypto.subtle){
        const enc = new TextEncoder();
        const buf = await crypto.subtle.digest('SHA-256', enc.encode(pw));
        return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
      }
    }catch(e){/* fallthrough to fallback */}
    return pw; // fallback: store plain (not recommended)
  }
  function getStoredAdminHash(){ return localStorage.getItem(ADMIN_HASH_KEY) }
  function setStoredAdminHash(h){ localStorage.setItem(ADMIN_HASH_KEY, h) }

   async function initAdmin(){
  try{
    const meRes = await fetch('/api/me', { credentials: 'include' });
    const me = await meRes.json();
    if(me && me.isAdmin){
      initAddWinnerForm();
      initManageWinners();
      initTabSwitching();
      initEditModalHandlers();
      await loadAndShowProfile();
      return;
    }
    // Not authenticated: show guest block + wire email flows
    const guest = document.getElementById('admin-guest');
    if(guest) guest.style.display = 'block';

    const loginBtn = document.getElementById('email-login');
    const regBtn = document.getElementById('email-register');

    loginBtn && loginBtn.addEventListener('click', async ()=>{
      const email = prompt('Enter your email:');
      if(!email) return;
      const password = prompt('Enter your password:');
      if(!password) return;
      try{
        const r = await fetch('/api/login', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          credentials:'include',
          body: JSON.stringify({ email, password })
        });
        const out = await r.json();
        if(!r.ok || !out.success){
          alert(out.message || 'Login failed. Make sure your email is verified.');
          return;
        }
        // Reload Admin UI
        window.location.reload();
      }catch(e){
        alert('Login failed.');
      }
    });

    regBtn && regBtn.addEventListener('click', async ()=>{
      const email = prompt('Enter your email to register:');
      if(!email) return;
      const name = prompt('Enter your display name (optional):') || '';
      const password = prompt('Create a strong password:');
      if(!password) return;
      try{
        const r = await fetch('/api/register', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ email, password, name })
        });
        const out = await r.json();
        if(!r.ok || !out.success){
          alert(out.message || 'Registration failed.');
          return;
        }
        alert('Registration successful! Check your email and click the verification link, then return here to login.');
      }catch(e){
        alert('Registration failed.');
      }
    });
  }catch(e){
    // Fallback: show guest block
    const guest = document.getElementById('admin-guest');
    if(guest) guest.style.display = 'block';
  }
}
  function initTabSwitching(){
    document.querySelectorAll('.tab-btn').forEach(btn=>{
      btn.addEventListener('click',()=>{
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
        btn.classList.add('active');
        byId(tab+'-tab').classList.add('active');
      })
    })
  }
  
 async function loadAndShowProfile(){
  console.log('loadAndShowProfile called');
  try{
    const prof = await apiProfileGet();
    console.log('Profile data:', prof);

    // Update header profile - always visible
    const navProfile = document.getElementById('nav-profile');
    const navAvatar = document.getElementById('nav-avatar');
    const navName = document.getElementById('nav-name');
    const navLogin = document.getElementById('nav-login');
    const navLogout = document.getElementById('nav-logout');

    if (navProfile) {
      navName.textContent = prof.name || prof.email || 'User';
      // Use profile.svg as default, only use uploaded photo if it exists and is local (not Google or efootball)
      navAvatar.src = prof.picture && !prof.picture.includes('googleusercontent.com') && !prof.picture.includes('efootball') ? prof.picture : 'images/profile.svg';
      // Hide login button when authenticated
      if (navLogin) navLogin.style.display = 'none';
      // Show profile and logout button
      navProfile.style.display = 'flex';
      console.log('User logged in, hiding login button');
      
      // Add logout functionality
      if (navLogout && !navLogout.dataset.wired) {
        navLogout.addEventListener('click', async ()=>{
          try {
            await fetch('/api/logout', { credentials: 'include' });
            // Clear any local session data
            document.cookie = 'user_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            window.location.href = 'index.html';
          } catch (e) {
            console.error('Logout error:', e);
            window.location.href = 'index.html';
          }
        });
        navLogout.dataset.wired = '1';
      }
    }

    // Interactive profile banner on index.html (only show on home page, not admin page)
    const banner = document.getElementById('profile-banner');
    const isHomePage = document.body.dataset.page === 'home';
    if (banner && isHomePage) {
      banner.style.display = 'block';
      const bName = document.getElementById('banner-name');
      const bEmail = document.getElementById('banner-email');
      const bAvatar = document.getElementById('banner-avatar');
      const bLogout = document.getElementById('banner-logout');
      const bEditBtn = document.getElementById('banner-edit-btn');
      const bView = document.getElementById('banner-view');
      const bEdit = document.getElementById('banner-edit');
      const bForm = document.getElementById('banner-form');
      const bCancelBtn = document.getElementById('banner-cancel-btn');

      // Populate view
      if (bName) bName.textContent = prof.name || prof.email || 'Profile';
      if (bEmail) bEmail.textContent = prof.email || '';
      if (bAvatar) bAvatar.src = prof.picture && !prof.picture.includes('googleusercontent.com') && !prof.picture.includes('efootball') ? prof.picture : 'images/profile.svg';

      // Logout
      if (bLogout && !bLogout.dataset.wired) {
        bLogout.addEventListener('click', async ()=>{
          await fetch('/api/logout', { credentials: 'include' });
          window.location.reload();
        });
        bLogout.dataset.wired = '1';
      }

      // Edit mode toggle
      if (bEditBtn && !bEditBtn.dataset.wired) {
        bEditBtn.addEventListener('click', ()=>{
          if (bForm) {
            bForm.elements['name'].value = prof.name || '';
          }
          if (bView) bView.style.display = 'none';
          if (bEdit) bEdit.style.display = 'block';
        });
        bEditBtn.dataset.wired = '1';
      }

      // Cancel edit
      if (bCancelBtn && !bCancelBtn.dataset.wired) {
        bCancelBtn.addEventListener('click', ()=>{
          if (bView) bView.style.display = 'block';
          if (bEdit) bEdit.style.display = 'none';
        });
        bCancelBtn.dataset.wired = '1';
      }

      // Save profile
      if (bForm && !bForm.dataset.wired) {
        bForm.addEventListener('submit', async (e)=>{
          e.preventDefault();
          const formData = new FormData(bForm);
          const name = formData.get('name')?.trim() || '';
          const avatarFile = formData.get('avatar');
          
          try{
            let response;
            if (avatarFile && avatarFile.size > 0) {
              // Upload file
              const uploadFormData = new FormData();
              uploadFormData.append('name', name);
              uploadFormData.append('avatar', avatarFile);
              
              response = await fetch('/api/profile', {
                method: 'PUT',
                credentials: 'include',
                body: uploadFormData
              });
            } else {
              // Update name only
              const payload = { name };
              response = await fetch('/api/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(payload)
              });
            }
            
            if (!response.ok) throw new Error('Update failed');
            const result = await response.json();
            alert('Profile updated.');
            // Use the returned profile data instead of making another API call
            if (result.profile) {
              await loadAndShowProfileWithProfile(result.profile);
            } else {
              await loadAndShowProfile();
            }
          }catch(err){
            alert('Failed to update profile.');
          }
        });
        bForm.dataset.wired = '1';
      }
    }

    // Update settings modal for profile (only on home page)
    if (isHomePage) {
      updateSettingsModal(prof);
    }
  }catch(e){
    console.log('Error loading profile, showing guest state:', e);
    // Not logged in: show guest profile
    const navProfile = document.getElementById('nav-profile');
    const navAvatar = document.getElementById('nav-avatar');
    const navName = document.getElementById('nav-name');
    const navLogin = document.getElementById('nav-login');

    if (navProfile) {
      navName.textContent = 'Guest User';
      navAvatar.src = 'images/profile.svg';
      // Show login button for guest
      if (navLogin) navLogin.style.display = 'inline-block';
    }
  }
}

async function loadAndShowProfileWithProfile(prof){
  console.log('loadAndShowProfileWithProfile called with:', prof);

  // Update header profile - always visible
  const navProfile = document.getElementById('nav-profile');
  const navAvatar = document.getElementById('nav-avatar');
  const navName = document.getElementById('nav-name');
  const navLogin = document.getElementById('nav-login');

  if (navProfile) {
    navName.textContent = prof.name || prof.email || 'User';
    // Use profile.svg as default, only use uploaded photo if it exists and is local
    navAvatar.src = prof.picture && !prof.picture.includes('googleusercontent.com') ? prof.picture : 'images/profile.svg';
    // Hide login button when authenticated
    if (navLogin) navLogin.style.display = 'none';
    console.log('User profile updated, hiding login button');
  }
}

function initAddWinnerForm(){
  const form = byId('winner-form');
  form.addEventListener('submit', async (ev)=>{
    ev.preventDefault();
    const fd = new FormData(form);
    
    try {
      const response = await fetch('/api/winners', {
        method: 'POST',
        credentials: 'include',
        body: fd
      });
      
      if (!response.ok) {
        throw new Error('Failed to add winner');
      }
      
      const result = await response.json();
      alert('Winner added successfully!');
      form.reset();
      renderManageWinners();
      // Update home page stats
      updateHomeStats();
    } catch (error) {
      console.error('Error adding winner:', error);
      alert('Failed to add winner. Please try again.');
    }
  })
}

function initManageWinners(){
  const searchEl = byId('manage-search');
  const shareLinkBtn = byId('generate-share-link');
  
  searchEl.addEventListener('input', ()=>renderManageWinners(searchEl.value));
  
  // Shareable link button handler
  if (shareLinkBtn && !shareLinkBtn.dataset.wired) {
    shareLinkBtn.addEventListener('click', () => {
      // Get current search filter if any
      const currentSearch = searchEl.value.trim();
      generateShareableLink(null, currentSearch);
    });
    shareLinkBtn.dataset.wired = '1';
  }
  
  renderManageWinners();
}

async function renderManageWinners(filter){
  const listEl = byId('winners-manage-list');
  const tpl = qs('#manage-winner-tpl');
  const data = await loadBackendData();
  listEl.innerHTML='';
  const q = (filter||'').toLowerCase();
  const matched = data.filter(it => !q || (it.name||'').toLowerCase().includes(q) || (it.title||'').toLowerCase().includes(q));
  if(matched.length===0){ listEl.innerHTML='<div class="muted">No winners yet.</div>'; return }
  matched.forEach(w=>{
    const node = tpl.content.cloneNode(true);
    const row = node.querySelector('.manage-winner-row');
    const nameEl = node.querySelector('.winner-name');
    const detailEl = node.querySelector('.winner-detail');
    const editBtn = node.querySelector('.edit-btn');
    const delBtn = node.querySelector('.btn.danger');
    nameEl.textContent = w.name || 'Unknown';
    detailEl.textContent = `${w.title || 'N/A'} • ${formatDate(w.date)} • Rank: ${w.rank}`;
    editBtn.addEventListener('click', ()=>openEditModal(w));
    delBtn.addEventListener('click', async ()=>{
      if(confirm(`Delete winner "${w.name}"?`)){
        try {
          const response = await fetch(`/api/winners/${w.id}`, {
            method: 'DELETE',
            credentials: 'include'
          });
          
          if (response.ok) {
            renderManageWinners();
            updateHomeStats();
          } else {
            alert('Failed to delete winner');
          }
        } catch (error) {
          console.error('Error deleting winner:', error);
          alert('Failed to delete winner');
        }
      }
    })
    listEl.appendChild(node);
  })
}

function openEditModal(winner){
  const modal = byId('edit-modal');
  const form = byId('edit-form');
  form.elements['id'].value = winner.id;
  form.elements['name'].value = winner.name || '';
  form.elements['wa'].value = winner.wa || '';
  form.elements['title'].value = winner.title || '';
  form.elements['rank'].value = winner.rank || '1';
  form.elements['score'].value = winner.score || '';
  form.elements['date'].value = winner.date || '';
  modal.style.display='flex';
}

function closeEditModal(){
  byId('edit-modal').style.display='none';
}

function initEditModalHandlers(){
  const modal = byId('edit-modal');
  const form = byId('edit-form');
  const closeBtn = qs('.modal-close', modal);
  const cancelBtn = qs('.modal-cancel', modal);
  closeBtn.addEventListener('click', closeEditModal);
  cancelBtn.addEventListener('click', closeEditModal);
  modal.addEventListener('click', (e)=>{
    if(e.target===modal) closeEditModal();
  })
  form.addEventListener('submit', async (ev)=>{
    ev.preventDefault();
    const fd = new FormData(form);
    const id = fd.get('id');
    const arr = loadData();
    const idx = arr.findIndex(x=>x.id===id);
    if(idx>-1){
      arr[idx].name = (fd.get('name')||'').trim();
      arr[idx].wa = (fd.get('wa')||'').trim();
      arr[idx].title = (fd.get('title')||'').trim();
      arr[idx].rank = fd.get('rank');
      arr[idx].score = (fd.get('score')||'').trim();
      arr[idx].date = fd.get('date');
      const file = fd.get('photo');
      if(file && file.size>0){
        arr[idx].photo = await fileToDataUrl(file);
      }
      saveData(arr);
      alert('Winner updated successfully!');
      closeEditModal();
      renderManageWinners();
    }
  })
}

function fileToDataUrl(file){
  return new Promise((resolve,reject)=>{
    const r = new FileReader(); 
    r.onload = ()=>resolve(r.result); 
    r.onerror=reject; 
    r.readAsDataURL(file);
  })
}

// Boot app
document.addEventListener('DOMContentLoaded', boot);
})();

