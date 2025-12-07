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
    if(t==='light') document.documentElement.classList.add('light'); else document.documentElement.classList.remove('light');
    localStorage.setItem(THEME_KEY, t);
  }

  // Page-specific boot
  function boot(){
    ensureSeed(); initTheme();
    const page = document.body.dataset.page;
    if(page==='home') initHome();
    if(page==='winners') initWinners();
    if(page==='admin') { initAdmin(); initEditModalHandlers(); }
  }

  // Home page - display stats
  function initHome(){
    const data = loadData();
    const tournaments = new Set(data.map(w=>w.title).filter(Boolean));
    const players = new Set(data.map(w=>w.name).filter(Boolean));
    byId('stat-winners').textContent = data.length;
    byId('stat-tournaments').textContent = tournaments.size;
    byId('stat-players').textContent = players.size;
  }

  // Winners page logic
  function initWinners(){
    const listEl = byId('winners-list');
    const tpl = qs('#winner-card-tpl');
    const search = byId('search');
    const shareSiteBtn = byId('share-site');
    const tournamentFilter = byId('tournament-filter');

    // Populate tournament filter dropdown
    function updateTournamentFilter(){
      const data = loadData();
      const tournaments = [...new Set(data.map(w=>w.title))].filter(Boolean).sort((a,b)=>b.localeCompare(a));
      tournamentFilter.innerHTML = '<option value="">All Tournaments</option>';
      tournaments.forEach(t=>{
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        tournamentFilter.appendChild(opt);
      })
    }

    function render(filter, tournamentFilter){
      const data = loadData().slice().sort((a,b)=> new Date(b.date) - new Date(a.date) || (b.createdAt||0)-(a.createdAt||0));
      listEl.innerHTML='';
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
    
    updateTournamentFilter();
    render();
    search&&search.addEventListener('input',e=>render(e.target.value, tournamentFilter.value));
    tournamentFilter&&tournamentFilter.addEventListener('change',e=>render(search.value, e.target.value));

    shareSiteBtn&&shareSiteBtn.addEventListener('click', ()=>{
      const url = location.href.replace(/winners\.html.*/,'winners.html');
      const text = `Check out our WA E-Football Winners Hall: ${url}`;
      shareWhatsApp(text);
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
      return `<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160' viewBox='0 0 100 100'><defs><linearGradient id='starGrad' x1='0' x2='1' y1='0' y2='1'><stop offset='0%' stop-color='%230099ff'/><stop offset='100%' stop-color='%2300ccff'/></linearGradient></defs><circle cx='50' cy='50' r='48' fill='url(%23starGrad)'/><path d='M50 20l12 30h32l-26 20 10 30L50 70 26 85l10-30-26-20h32z' fill='%23ffff00'/><circle cx='50' cy='50' r='2' fill='%23fff'/></svg>`;
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
    // If no admin configured, prompt to create one
    const stored = getStoredAdminHash();
    if(!stored){
      const create = prompt('No admin account found. Create admin password (will be stored locally):');
      if(!create){ alert('Admin setup cancelled. Redirecting home.'); window.location.href='index.html'; return }
      const confirm = prompt('Confirm password:');
      if(create !== confirm){ alert('Passwords did not match. Redirecting home.'); window.location.href='index.html'; return }
      const h = await hashPassword(create);
      setStoredAdminHash(h);
      alert('Admin password saved locally. You will be prompted to login now.');
    }

    // Prompt for login
    const pw = prompt('Enter admin password:');
    if(!pw){ alert('Login cancelled.'); window.location.href='index.html'; return }
    const hpw = await hashPassword(pw);
    const storedNow = getStoredAdminHash();
    if(hpw !== storedNow && pw !== ADMIN_PASSWORD_FALLBACK){
      alert('Incorrect password. Admin access denied.'); window.location.href='index.html'; return
    }

    // If we reach here, admin access granted
    initAddWinnerForm();
    initManageWinners();
    initTabSwitching();
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

  function initAddWinnerForm(){
    const form = byId('winner-form');
    form.addEventListener('submit', async (ev)=>{
      ev.preventDefault();
      const fd = new FormData(form);
      const entry = {
        id: cryptoId(),
        name: (fd.get('name')||'').trim(),
        wa: (fd.get('wa')||'').trim(),
        title: (fd.get('title')||'').trim(),
        rank: fd.get('rank'),
        score: (fd.get('score')||'').trim(),
        date: fd.get('date') || new Date().toISOString().slice(0,10),
        photo: null,
        createdAt: Date.now()
      };
      const file = fd.get('photo');
      if(file && file.size>0){
        entry.photo = await fileToDataUrl(file);
      }
      const arr = loadData();
      arr.push(entry);
      saveData(arr);
      alert('Winner added successfully!');
      form.reset();
      renderManageWinners();
    })
  }

  function initManageWinners(){
    const searchEl = byId('manage-search');
    searchEl.addEventListener('input', ()=>renderManageWinners(searchEl.value));
    renderManageWinners();
  }

  function renderManageWinners(filter){
    const listEl = byId('winners-manage-list');
    const tpl = qs('#manage-winner-tpl');
    const data = loadData().slice().sort((a,b)=> new Date(b.date) - new Date(a.date));
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
      delBtn.addEventListener('click', ()=>{
        if(confirm(`Delete winner "${w.name}"?`)){
          const arr = loadData();
          const idx = arr.findIndex(x=>x.id===w.id);
          if(idx>-1) arr.splice(idx,1);
          saveData(arr);
          renderManageWinners();
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
      const r = new FileReader(); r.onload = ()=>resolve(r.result); r.onerror=reject; r.readAsDataURL(file);
    })
  }

  // Boot app
  document.addEventListener('DOMContentLoaded', boot);
})();