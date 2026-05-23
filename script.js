const API_BASE = '/api/query';
function esc(t){if(!t)return'';return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');}
async function apiCall(action, params={}){
  const headers={'Content-Type':'application/json'};
  const token=localStorage.getItem('sb-token');
  if(token) headers['Authorization']='Bearer '+token;
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),10000);
  try{
    const res=await fetch(API_BASE,{method:'POST',headers,body:JSON.stringify({action,...params}),signal:controller.signal});
    clearTimeout(timeout);
    const json=await res.json();
    if(!res.ok) throw new Error(json.error||'Request failed');
    return json.data!==undefined?json.data:json;
  }catch(err){clearTimeout(timeout);throw err;}
}
function updateMobilePanel(links){
  const nav=document.getElementById('mobile-nav-links'),footer=document.getElementById('mobile-nav-footer');
  if(!nav||!footer)return;
  nav.innerHTML=(links||[]).map(l=>`<a href="${esc(l.href)}"><i class="fa-solid fa-chevron-right"></i> ${esc(l.label)}</a>`).join('');
  const token=localStorage.getItem('sb-token');
  footer.innerHTML=token?'<button class="mobile-signout-btn" onclick="signOut()"><i class="fa-solid fa-right-from-bracket"></i> Sign Out</button>':'<a href="#" class="mobile-signin-btn" onclick="showAuthForm(\'signin\');return false;"><i class="fa-solid fa-right-to-bracket"></i> Sign In</a><a href="#" class="mobile-signup-btn" onclick="showAuthForm(\'signup\');return false;"><i class="fa-solid fa-user-plus"></i> Create Account</a>';
}
window.signOut=async function(){try{await apiCall('signout');}catch(e){}localStorage.removeItem('sb-token');localStorage.removeItem('sb-email');updateMobilePanel([]);location.href='/';};
window.showAuthForm=function(mode){
  const existing=document.getElementById('auth-modal');if(existing)existing.remove();
  const modal=document.createElement('div');modal.id='auth-modal';modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');
  modal.style.cssText='position:fixed;inset:0;z-index:300;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.8);';
  modal.innerHTML=`<div style="background:var(--clr-navy-card);border:2px solid var(--clr-cyan);border-radius:var(--radius-lg);padding:2rem;max-width:380px;width:90%;position:relative;backdrop-filter:blur(20px);"><button id="close-auth" style="position:absolute;top:0.5rem;right:0.5rem;background:none;border:none;color:var(--clr-text-dim);cursor:pointer;font-size:1.2rem;">✕</button><h3 style="color:var(--clr-cyan);margin-bottom:1.2rem;text-align:center;">${mode==='signin'?'Sign In':'Create Account'}</h3><form id="auth-form" style="display:flex;flex-direction:column;gap:1rem;" autocomplete="on"><input type="email" id="auth-email" class="form-input" placeholder="Email" required autocomplete="email"><input type="password" id="auth-password" class="form-input" placeholder="Password (min 6 chars)" minlength="6" required autocomplete="${mode==='signin'?'current-password':'new-password'}"><button type="submit" class="btn-primary" style="justify-content:center;">${mode==='signin'?'Sign In':'Create Account'}</button></form><p style="text-align:center;margin-top:1rem;color:var(--clr-text-dim);font-size:0.9rem;">${mode==='signin'?"No account? <a href='#' id='switch-mode' style='color:var(--clr-magenta);'>Sign up</a>":"Have account? <a href='#' id='switch-mode' style='color:var(--clr-magenta);'>Sign in</a>"}</p><p id="auth-error" style="color:#ff4444;text-align:center;margin-top:0.5rem;display:none;"></p></div>`;
  document.body.appendChild(modal);
  document.getElementById('close-auth').onclick=()=>modal.remove();
  modal.addEventListener('click',(e)=>{if(e.target===modal)modal.remove();});
  document.addEventListener('keydown',function escClose(e){if(e.key==='Escape'){modal.remove();document.removeEventListener('keydown',escClose);}});
  document.getElementById('switch-mode').onclick=(e)=>{e.preventDefault();modal.remove();showAuthForm(mode==='signin'?'signup':'signin');};
  document.getElementById('auth-form').onsubmit=async(e)=>{
    e.preventDefault();const email=document.getElementById('auth-email').value.trim(),password=document.getElementById('auth-password').value,errEl=document.getElementById('auth-error');errEl.style.display='none';
    try{
      const action=mode==='signin'?'signin':'signup',data=await apiCall(action,{email,password});
      if(data.session){localStorage.setItem('sb-token',data.session.access_token);localStorage.setItem('sb-email',data.user.email);modal.remove();updateMobilePanel([]);location.reload();}
      else if(mode==='signup'){errEl.textContent='Check your email to confirm signup.';errEl.style.display='block';}
    }catch(err){errEl.textContent=err.message;errEl.style.display='block';}
  };
};
function initCarousel(count){
  const slides=document.querySelectorAll('.carousel-slide'),dots=document.querySelectorAll('.carousel-dot');
  if(count<=1)return;
  let current=0,interval;
  function go(i){slides[current].classList.remove('active');dots[current]?.classList.remove('active');current=i;slides[current].classList.add('active');dots[current]?.classList.add('active');}
  function nxt(){go((current+1)%count);}
  function prv(){go((current-1+count)%count);}
  function reset(){clearInterval(interval);interval=setInterval(nxt,5000);}
  document.querySelector('.carousel-prev')?.addEventListener('click',()=>{prv();reset();});
  document.querySelector('.carousel-next')?.addEventListener('click',()=>{nxt();reset();});
  dots.forEach(d=>d.addEventListener('click',()=>{go(+d.dataset.index);reset();}));
  document.addEventListener('keydown',(e)=>{if(e.key==='ArrowLeft'){prv();reset();}else if(e.key==='ArrowRight'){nxt();reset();}});
  reset();
}
function initUI(){
  const tt=document.getElementById('theme-toggle'),icon=tt.querySelector('i');
  if(localStorage.getItem('theme')==='dark'){document.body.classList.add('dark-mode');icon.classList.replace('fa-moon','fa-sun');}
  tt.onclick=()=>{document.body.classList.toggle('dark-mode');const dark=document.body.classList.contains('dark-mode');icon.classList.replace(dark?'fa-moon':'fa-sun',dark?'fa-sun':'fa-moon');localStorage.setItem('theme',dark?'dark':'light');};
  const mt=document.getElementById('mobile-toggle'),mp=document.getElementById('mobile-nav-panel'),mo=document.getElementById('mobile-nav-overlay'),closeBtn=document.getElementById('mobile-close-btn');
  function open(){mp.classList.add('active');mo.classList.add('active');document.body.style.overflow='hidden';mt.setAttribute('aria-expanded','true');}
  function close(){mp.classList.remove('active');mo.classList.remove('active');document.body.style.overflow='';mt.setAttribute('aria-expanded','false');}
  mt.onclick=()=>mp.classList.contains('active')?close():open();
  mo.onclick=close;closeBtn.onclick=close;
  document.addEventListener('keydown',e=>{if(e.key==='Escape')close();});
  const bb=document.getElementById('back-to-top');
  window.addEventListener('scroll',()=>{bb.classList.toggle('visible',window.scrollY>500);}, {passive:true});
  bb.onclick=()=>window.scrollTo({top:0,behavior:'smooth'});
  document.querySelectorAll('a[href^="#"]').forEach(a=>a.addEventListener('click',function(e){if(this.getAttribute('href')==='#')return;e.preventDefault();document.querySelector(this.getAttribute('href'))?.scrollIntoView({behavior:'smooth'});}));
  const obs=new IntersectionObserver(entries=>{entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');obs.unobserve(e.target);}})},{threshold:0.1});
  document.querySelectorAll('.reveal').forEach(el=>obs.observe(el));
  document.getElementById('contact-form').onsubmit=async function(e){
    e.preventDefault();const fd={name:document.getElementById('contact-name').value.trim(),email:document.getElementById('contact-email').value.trim(),subject:document.getElementById('contact-subject').value.trim(),message:document.getElementById('contact-message').value.trim()};
    const errEl=document.getElementById('form-error'),successEl=document.getElementById('form-success');
    errEl.style.display='none';successEl.style.display='none';
    if(!fd.name||!fd.email||!fd.subject||!fd.message){errEl.textContent='All fields are required.';errEl.style.display='block';return;}
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fd.email)){errEl.textContent='Please enter a valid email.';errEl.style.display='block';return;}
    try{await apiCall('submit_contact',{formData:fd});successEl.textContent='✓ Message sent successfully!';successEl.style.display='block';this.reset();setTimeout(()=>successEl.style.display='none',5000);}
    catch(err){errEl.textContent='Failed: '+err.message;errEl.style.display='block';}
  };
  document.getElementById('newsletter-form').onsubmit=async function(e){
    e.preventDefault();const email=this.querySelector('input').value.trim();
    if(!email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){alert('Valid email required.');return;}
    try{await apiCall('subscribe_newsletter',{formData:{email}});alert('✓ Subscribed successfully!');this.reset();}catch(err){alert('Subscribed!');this.reset();}
  };
  initFilterUI();
}
function initFilterUI(){
  const toggleBtn=document.getElementById('filter-toggle-btn'),dropdown=document.getElementById('filter-dropdown');
  toggleBtn.addEventListener('click',()=>{const open=dropdown.style.display!=='none';dropdown.style.display=open?'none':'flex';toggleBtn.classList.toggle('open',!open);});
  document.querySelectorAll('.filter-accordion-btn').forEach(btn=>{btn.addEventListener('click',()=>{const options=btn.nextElementSibling;const isOpen=options.classList.contains('open');document.querySelectorAll('.filter-options').forEach(opt=>opt.classList.remove('open'));document.querySelectorAll('.filter-accordion-btn').forEach(b=>b.classList.remove('open'));if(!isOpen){options.classList.add('open');btn.classList.add('open');}});});
  document.querySelectorAll('.filter-option input').forEach(input=>{input.addEventListener('change',()=>{const sel=document.getElementById('selected-'+input.name);if(sel)sel.textContent=input.parentElement.textContent.trim();});});
  const searchInput=document.getElementById('resource-search');
  searchInput.addEventListener('input',()=>renderFilteredResources());
  document.getElementById('filter-apply').addEventListener('click',()=>{window.resourceFilters={level:document.querySelector('input[name="level"]:checked')?.value||'',category:document.querySelector('input[name="category"]:checked')?.value||''};renderFilteredResources();});
  document.getElementById('filter-clear').addEventListener('click',()=>{document.querySelectorAll('.filter-option input').forEach(i=>i.checked=false);document.querySelectorAll('.filter-option input[value=""]').forEach(i=>i.checked=true);document.getElementById('selected-level').textContent='All Levels';document.getElementById('selected-category').textContent='All Categories';document.getElementById('resource-search').value='';window.resourceFilters={level:'',category:''};renderFilteredResources();});
}
async function loadFilters(){
  try{
    const data=await apiCall('get_filter_options');
    const categories=data?.categories||[];
    const container=document.getElementById('filter-options-category');
    if(container&&categories.length){
      const allOption=container.querySelector('input[value=""]').parentElement;
      container.innerHTML='';container.appendChild(allOption);
      categories.forEach(cat=>{const label=document.createElement('label');label.className='filter-option';label.innerHTML=`<input type="radio" name="category" value="${esc(cat)}"> ${esc(cat)}`;label.querySelector('input').addEventListener('change',()=>{document.getElementById('selected-category').textContent=cat;});container.appendChild(label);});
    }
  }catch(err){console.error('Filter load error:',err);}
}
window.resourceFilters={level:'',category:''};
window.allResources=[];
function filterResources(){
  const search=document.getElementById('resource-search').value.toLowerCase();
  const {level,category}=window.resourceFilters;
  return window.allResources.filter(r=>{
    const matchSearch=!search||(r.title||'').toLowerCase().includes(search)||(r.description||'').toLowerCase().includes(search)||(r.tag||'').toLowerCase().includes(search);
    const matchLevel=!level||r.level===level;
    const matchCategory=!category||r.category===category;
    return matchSearch&&matchLevel&&matchCategory;
  });
}
function groupResources(resources){
  const groups={};
  resources.forEach(item=>{const s=(item.section_type||'Resources').trim();if(!groups[s])groups[s]=[];groups[s].push(item);});
  return groups;
}
function renderFilteredResources(){
  const container=document.getElementById('resources-container');
  const filtered=filterResources();
  if(!filtered.length){container.innerHTML='<p style="text-align:center;padding:2rem;color:var(--clr-text-dim);">No resources match your criteria.</p>';return;}
  const groups=groupResources(filtered);
  renderResourcesHTML(container,groups);
}
function renderResourcesHTML(container,groups){
  container.innerHTML=Object.entries(groups).map(([name,items])=>`<div style="margin-bottom:3rem;"><h2 style="font-family:'Playfair Display',serif;font-size:1.6rem;color:var(--clr-cyan);margin-bottom:1.25rem;padding-left:1rem;border-left:4px solid var(--clr-magenta);">${esc(name)}</h2><div class="resources-grid" role="list">${items.map(item=>{
    const fileIcon=(item.file_url||'').toLowerCase().endsWith('.pdf')?'fa-file-pdf':'fa-file';
    return `<div class="resource-card" role="listitem" data-id="${item.id}"><div style="font-size:2.2rem;color:var(--clr-magenta);"><i class="fa-solid ${fileIcon}"></i></div><a href="#" class="resource-title-link" style="font-weight:700;font-size:1.05rem;color:var(--clr-white);text-decoration:none;">${esc(item.title||'Untitled')}</a><p style="font-size:0.9rem;color:var(--clr-text-dim);flex-grow:1;">${esc(item.description||'')}</p><div style="display:flex;flex-wrap:wrap;gap:0.6rem;font-size:0.8rem;color:var(--clr-text-muted);"><span><i class="fa-regular fa-user"></i> ${esc(item.author||'Unknown')}</span><span><i class="fa-regular fa-calendar"></i> ${item.created_at?new Date(item.created_at).toLocaleDateString():'N/A'}</span><span><i class="fa-regular fa-file"></i> ${esc(item.file_size||'N/A')}</span></div><div style="display:flex;align-items:center;justify-content:space-between;padding-top:1rem;border-top:1px solid var(--clr-border-glow);"><a href="${esc(item.file_url||'#')}" class="btn-download" download target="_blank" rel="noopener"><i class="fa-solid fa-download"></i> Download</a><div style="display:flex;gap:0.4rem;"><a href="#" class="share-btn" aria-label="Share on Facebook"><i class="fa-brands fa-facebook-f"></i></a><a href="#" class="share-btn" aria-label="Share on X"><i class="fa-brands fa-x-twitter"></i></a><a href="#" class="share-btn" aria-label="Share on WhatsApp"><i class="fa-brands fa-whatsapp"></i></a></div></div></div>`;
  }).join('')}</div></div>`).join('');
  container.querySelectorAll('.resource-title-link').forEach(link=>link.addEventListener('click',function(e){e.preventDefault();const card=this.closest('.resource-card');if(card)showResourceModal(card.dataset.id);}));
}
function showResourceModal(id){
  const item=window.allResources.find(r=>r.id==id);
  if(!item)return;
  document.getElementById('resource-modal-content').innerHTML=`<h2 style="font-family:'Playfair Display',serif;color:var(--clr-white);margin-bottom:1rem;">${esc(item.title)}</h2><p style="color:var(--clr-text-dim);margin-bottom:1rem;">${esc(item.description)}</p><div style="margin-bottom:1rem;"><span style="color:var(--clr-text-muted);">Author:</span> ${esc(item.author||'Unknown')}</div><div style="margin-bottom:1rem;"><span style="color:var(--clr-text-muted);">Level:</span> ${esc(item.level||'N/A')} | <span style="color:var(--clr-text-muted);">Category:</span> ${esc(item.category||'N/A')}</div><div style="margin-bottom:1rem;"><span style="color:var(--clr-text-muted);">File size:</span> ${esc(item.file_size||'N/A')}</div>${item.file_url?`<a href="${esc(item.file_url)}" class="btn-primary" download target="_blank" rel="noopener"><i class="fa-solid fa-download"></i> Download</a>`:''}`;
  document.getElementById('resource-modal-overlay').classList.add('active');
  document.body.style.overflow='hidden';
}
document.getElementById('resource-modal-close').addEventListener('click',()=>{document.getElementById('resource-modal-overlay').classList.remove('active');document.body.style.overflow='';});
document.getElementById('resource-modal-overlay').addEventListener('click',function(e){if(e.target===this){this.classList.remove('active');document.body.style.overflow='';}});
async function buildResources(){
  const container=document.getElementById('resources-container');
  container.innerHTML='<p style="text-align:center;padding:2rem;color:var(--clr-text-dim);">Loading resources…</p>';
  try{
    const data=await apiCall('get_resources');
    if(!data||!data.length){container.innerHTML='<p style="text-align:center;padding:2rem;color:var(--clr-text-dim);">No resources found.</p>';return;}
    window.allResources=data;
    renderFilteredResources();
  }catch(err){container.innerHTML='<p style="text-align:center;padding:2rem;color:var(--clr-magenta);">Failed to load resources.</p>';console.error('Resources error:',err);}
}
async function loadPublicStats(){
  try{
    const stats=await apiCall('get_public_stats');
    if(stats){
      const grid=document.getElementById('stats-grid');grid.innerHTML='';
      const items=[{value:stats.resources_count||0,label:'Resources'},{value:stats.users_count||0,label:'Learners'},{value:stats.downloads_count||0,label:'Downloads'},{value:stats.quiz_attempts||0,label:'Quiz Attempts'}];
      items.forEach(item=>{const div=document.createElement('div');div.setAttribute('role','listitem');div.innerHTML=`<div class="stat-number" data-target="${item.value}">0</div><div style="color:var(--clr-text-dim);margin-top:0.25rem;font-size:0.875rem;">${item.label}</div>`;grid.appendChild(div);});
      animateStats();
    }
  }catch(e){document.getElementById('stats-grid').innerHTML='<p style="text-align:center;color:var(--clr-text-dim);">Statistics coming soon.</p>';}
}
function animateStats(){
  const counters=document.querySelectorAll('.stat-number[data-target]');
  if(!counters.length)return;
  const observer=new IntersectionObserver((entries)=>{entries.forEach(entry=>{if(entry.isIntersecting){const el=entry.target,target=+el.dataset.target;if(target===0){el.textContent='0';observer.unobserve(el);return;}const duration=1500,step=target/(duration/16);let current=0;const update=()=>{current+=step;if(current<target){el.textContent=Math.floor(current);requestAnimationFrame(update);}else{el.textContent=target;}};update();observer.unobserve(el);}})},{threshold:0.5});
  counters.forEach(el=>observer.observe(el));
}
function updateAuthUI(){
  const token=localStorage.getItem('sb-token'),mainNav=document.getElementById('main-nav'),mobileFooter=document.getElementById('mobile-nav-footer');
  if(token){
    const email=localStorage.getItem('sb-email')||'User',name=email.split('@')[0].replace(/[._]/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
    const userMenu=`<li class="user-dropdown"><button class="user-dropdown-trigger"><i class="fa-solid fa-user"></i> ${esc(name)}</button><div class="user-dropdown-menu"><a href="/dashboard">Dashboard</a><a href="#" onclick="signOut();return false;">Sign Out</a></div></li>`;
    if(mainNav){const existing=mainNav.querySelector('.user-dropdown');if(existing)existing.remove();mainNav.insertAdjacentHTML('beforeend',userMenu);}
    if(mobileFooter)mobileFooter.innerHTML='<button class="mobile-signout-btn" onclick="signOut()"><i class="fa-solid fa-right-from-bracket"></i> Sign Out</button>';
  }else{
    if(mainNav){const existing=mainNav.querySelector('.user-dropdown');if(existing)existing.remove();}
    if(mobileFooter)mobileFooter.innerHTML='<a href="#" class="mobile-signin-btn" onclick="showAuthForm(\'signin\');return false;">Sign In</a><a href="#" class="mobile-signup-btn" onclick="showAuthForm(\'signup\');return false;">Create Account</a>';
  }
}
document.addEventListener('DOMContentLoaded',async ()=>{
  document.getElementById('current-year').textContent=new Date().getFullYear();
  initUI();
  try{
    const sections=await apiCall('get_all_site_sections');
    if(sections){
      if(sections.site_config&&sections.site_config.logo_url){
        const logoUrl=sections.site_config.logo_url;
        const applyLogo=(selector)=>{const el=document.querySelector(selector);if(el)el.innerHTML=`<img src="${esc(logoUrl)}" alt="AliverBiopharm" style="height:160px;width:auto;max-width:60vw;object-fit:contain;display:block;margin:-50px 0;" onerror="this.parentElement.innerHTML='<div class=\\'logo-icon\\' aria-hidden=\\'true\\'><svg width=\\'18\\' height=\\'18\\' fill=\\'none\\' stroke=\\'#fff\\' stroke-width=\\'2\\' viewBox=\\'0 0 24 24\\'><path stroke-linecap=\\'round\\' stroke-linejoin=\\'round\\' d=\\'M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15M14.25 3.104c.251.023.501.05.75.082\\'/></svg></div>Aliver<span class=\\'g-text\\'>Biopharm</span>';">`;};
        applyLogo('.site-header .logo-link');applyLogo('.mobile-nav-header .logo-link');applyLogo('.footer-fat .logo-link');
      }
      if(sections.navigation){
        const links=sections.navigation.links||[];
        document.getElementById('main-nav').innerHTML=links.map(l=>`<li><a href="${esc(l.href)}">${esc(l.label)}</a></li>`).join('');
        updateMobilePanel(links);
      }
      if(sections.hero&&sections.hero.slides&&sections.hero.slides.length){
        const slides=sections.hero.slides;
        document.getElementById('home').innerHTML=slides.map((s,i)=>`<div class="carousel-slide${i===0?' active':''}" style="background-image:url('${esc(s.background_image)}');"><div class="slide-overlay"><h1 class="font-display font-black text-4xl md:text-6xl mb-4" style="color:#fff;text-shadow:0 2px 16px rgba(0,0,0,0.9);">${esc(s.title)}</h1><p class="text-lg md:text-xl max-w-2xl mb-8" style="color:#fff;text-shadow:0 2px 12px rgba(0,0,0,0.8);">${esc(s.subtitle)}</p><a href="${esc(s.cta_link)}" class="btn-primary"><i class="${esc(s.icon||'fa-solid fa-arrow-right')}"></i> ${esc(s.cta_text)}</a></div></div>`).join('')+'<button class="carousel-arrow carousel-prev"><i class="fa-solid fa-chevron-left"></i></button><button class="carousel-arrow carousel-next"><i class="fa-solid fa-chevron-right"></i></button><div class="carousel-controls">'+slides.map((_,i)=>`<span class="carousel-dot${i===0?' active':''}" data-index="${i}"></span>`).join('')+'</div>';
        initCarousel(slides.length);
      }
      if(sections.team&&sections.team.members&&sections.team.members.length){
        document.getElementById('team-grid').innerHTML=sections.team.members.map(p=>`<div class="card team-card text-center"><div class="team-avatar">${p.avatar_url?`<img src="${esc(p.avatar_url)}" alt="${esc(p.name)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" onerror="this.parentElement.innerHTML='<i class=\\'fa-solid fa-user-tie\\'></i>'">`:'<i class="fa-solid fa-user-tie"></i>'}</div><h3 style="font-family:'Playfair Display',serif;font-weight:700;font-size:1.15rem;color:var(--clr-white);margin-top:0.5rem;">${esc(p.name)}${p.title?', '+esc(p.title):''}</h3><p style="font-size:0.84rem;line-height:1.7;color:var(--clr-text-dim);margin-top:0.5rem;">${esc(p.bio||'')}</p></div>`).join('');
      }else document.getElementById('team-grid').innerHTML='<p style="text-align:center;grid-column:1/-1;color:var(--clr-text-dim);">Faculty information coming soon.</p>';
      if(sections.testimonials&&sections.testimonials.quotes&&sections.testimonials.quotes.length){
        const q=sections.testimonials.quotes;let c=0;
        function show(i){c=i;document.getElementById('testimonial-slider').innerHTML=`<blockquote class="testimonial-quote">"${esc(q[i].text)}"</blockquote><cite class="testimonial-author">— ${esc(q[i].author)}</cite><div class="testimonial-nav">${q.map((_,j)=>`<span class="testimonial-dot${j===i?' active':''}" data-index="${j}"></span>`).join('')}</div>`;document.querySelectorAll('.testimonial-dot').forEach(d=>d.onclick=()=>show(+d.dataset.index));}
        show(0);setInterval(()=>show((c+1)%q.length),5000);
      }else document.getElementById('testimonial-slider').innerHTML='<p style="color:var(--clr-text-dim);">Student success stories coming soon.</p>';
      if(sections.pricing&&sections.pricing.plans&&sections.pricing.plans.length){
        document.getElementById('pricing-grid').innerHTML=sections.pricing.plans.map(pl=>`<div class="card pricing-card${pl.featured?' featured':''}"><h3>${esc(pl.name)}</h3><p style="font-size:0.84rem;color:var(--clr-text-dim);">${esc(pl.description||'')}</p><div class="price my-3">${esc(pl.price)}<span style="font-size:1rem;color:var(--clr-text-dim);">${esc(pl.period||'')}</span></div><ul class="pricing-features">${(pl.features||[]).map(f=>`<li><i class="fa-solid fa-check"></i> ${esc(f)}</li>`).join('')}</ul><button class="btn-primary w-full justify-center mt-4">${esc(pl.cta_text||'Subscribe')}</button></div>`).join('');
      }else document.getElementById('pricing-grid').innerHTML='<p style="text-align:center;grid-column:1/-1;color:var(--clr-text-dim);">Plans being updated.</p>';
      if(sections.blog&&sections.blog.posts&&sections.blog.posts.length){
        document.getElementById('blog-grid').innerHTML=sections.blog.posts.map(p=>`<article class="card">${p.image_url?`<img src="${esc(p.image_url)}" alt="${esc(p.title)}" style="width:100%;height:200px;object-fit:cover;border-radius:var(--radius-md);margin-bottom:1rem;">`:''}<div class="flex gap-4 text-xs" style="color:var(--clr-text-muted);margin-bottom:0.5rem;"><span><i class="fa-regular fa-calendar"></i> ${esc(p.date||'')}</span><span><i class="fa-regular fa-user"></i> ${esc(p.author||'')}</span></div><h3 style="font-family:'Playfair Display',serif;font-weight:700;font-size:1.15rem;color:var(--clr-white);">${esc(p.title)}</h3><p style="font-size:0.84rem;line-height:1.7;color:var(--clr-text-dim);">${esc(p.excerpt||'')}</p><a href="#" style="color:var(--clr-magenta);font-weight:600;font-size:0.875rem;">Read Article <i class="fa-solid fa-arrow-right"></i></a></article>`).join('');
      }else document.getElementById('blog-grid').innerHTML='<p style="text-align:center;grid-column:1/-1;color:var(--clr-text-dim);">New articles coming soon.</p>';
      if(sections.faq&&sections.faq.items&&sections.faq.items.length){
        document.getElementById('faq-list').innerHTML=sections.faq.items.map(i=>`<div class="faq-item"><button class="faq-question" onclick="this.parentElement.classList.toggle('active')"><span>${esc(i.question)}</span><span style="color:var(--clr-cyan);">+</span></button><div class="faq-answer" role="region"><p>${esc(i.answer)}</p></div></div>`).join('');
      }else document.getElementById('faq-list').innerHTML='<p style="text-align:center;color:var(--clr-text-dim);">FAQ coming soon.</p>';
      if(sections.footer){
        const fd=sections.footer;
        document.getElementById('footer-grid').innerHTML=(fd.columns||[]).map(c=>`<div><h4 style="font-weight:700;color:var(--clr-white);font-size:0.9rem;margin-bottom:16px;">${esc(c.heading)}</h4><ul style="list-style:none;display:flex;flex-direction:column;gap:10px;">${(c.items||[]).map(i=>`<li><a href="${esc(i.href||'#')}" style="font-size:0.875rem;color:var(--clr-text-dim);text-decoration:none;">${i.icon?`<i class="${esc(i.icon)}" style="color:var(--clr-magenta);margin-right:0.5rem;"></i>`:''}${esc(i.label)}</a></li>`).join('')}</ul></div>`).join('');
        document.getElementById('footer-social').innerHTML=(fd.social_links||[]).map(s=>`<a href="${esc(s.url)}" aria-label="${esc(s.platform)}" target="_blank" rel="noopener noreferrer"><i class="${esc(s.icon)}"></i></a>`).join('');
      }
      if(sections.contact&&sections.contact.info){
        document.getElementById('contact-info-card').innerHTML+=sections.contact.info.map(c=>`<div style="display:flex;align-items:center;gap:1rem;padding:0.8rem 0;border-bottom:1px solid var(--clr-border-glow);"><div class="contact-icon"><i class="${esc(c.icon)}"></i></div><div><div style="font-size:0.7rem;color:var(--clr-text-muted);">${esc(c.label)}</div><a href="${esc(c.href)}" style="color:var(--clr-white);text-decoration:none;">${esc(c.value)}</a></div></div>`).join('');
      }
      if(sections.site_config&&sections.site_config.announcement){
        document.getElementById('announcement-text').textContent=sections.site_config.announcement;
        document.getElementById('hero-announcement').classList.add('visible');
      }
    }
  }catch(err){console.error('Section load error:',err);}
  await loadFilters();
  await buildResources();
  loadPublicStats();
  updateAuthUI();
});
(function(){
  let chatRoomId=null,chatPollInterval=null;
  const bubbleBtn=document.getElementById('chat-bubble-btn'),chatWindow=document.getElementById('chat-window');
  const closeBtn=document.getElementById('chat-close-btn'),chatBody=document.getElementById('chat-body');
  const chatInput=document.getElementById('chat-input'),sendBtn=document.getElementById('chat-send-btn');
  const clearBtn=document.getElementById('chat-clear-btn'),statusEl=document.getElementById('chat-status');
  const adminDot=document.getElementById('admin-dot');
  bubbleBtn.addEventListener('click',()=>{const open=chatWindow.classList.contains('open');if(open)chatWindow.classList.remove('open');else{chatWindow.classList.add('open');if(!chatRoomId)requestChat();}});
  closeBtn.addEventListener('click',()=>chatWindow.classList.remove('open'));
  async function requestChat(){
    if(!localStorage.getItem('sb-token')){statusEl.textContent='Please sign in.';return;}
    statusEl.textContent='Connecting...';
    try{
      const res=await apiCall('request_chat');
      chatRoomId=res.room_id;
      if(res.status==='active'){statusEl.textContent='Chat started!';enableInput();loadMessages();startPolling();}
      else{statusEl.textContent='Waiting for an admin...';disableInput();const waitInterval=setInterval(async()=>{if(!chatRoomId){clearInterval(waitInterval);return;}try{const msgs=await apiCall('get_chat_messages',{room_id:chatRoomId});if(Array.isArray(msgs)&&msgs.length>0){clearInterval(waitInterval);statusEl.textContent='Chat started!';enableInput();loadMessages();startPolling();}}catch(e){}},3000);}
    }catch(e){statusEl.textContent='Failed to connect.';console.error('Chat request error:',e);}
  }
  function enableInput(){chatInput.disabled=false;sendBtn.disabled=false;}
  function disableInput(){chatInput.disabled=true;sendBtn.disabled=true;}
  async function loadMessages(){if(!chatRoomId)return;try{const msgs=await apiCall('get_chat_messages',{room_id:chatRoomId});renderMessages(msgs);}catch(e){}}
  function renderMessages(msgs){
    chatBody.innerHTML='';
    if(!msgs||!msgs.length){chatBody.innerHTML='<div class="chat-status">No messages yet.</div>';return;}
    msgs.forEach(m=>{
      const div=document.createElement('div');
      div.className='chat-msg '+(m.sender_type==='user'?'user':'admin');
      div.innerHTML=`<strong>${m.sender_type==='user'?'You':'Admin'}:</strong> ${escHTML(m.content)}`+(m.sender_type==='user'?`<button class="chat-clear-btn" style="font-size:0.6rem;margin-left:4px;" data-msgid="${m.id}">✖</button>`:'');
      chatBody.appendChild(div);
    });
    document.querySelectorAll('.chat-clear-btn[data-msgid]').forEach(btn=>{btn.addEventListener('click',async function(e){e.stopPropagation();await apiCall('delete_chat_message',{message_id:this.dataset.msgid});loadMessages();});});
    chatBody.scrollTop=chatBody.scrollHeight;
  }
  function escHTML(str){return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  sendBtn.addEventListener('click',async()=>{const msg=chatInput.value.trim();if(!msg||!chatRoomId)return;try{await apiCall('send_chat_message',{room_id:chatRoomId,message:msg});chatInput.value='';loadMessages();}catch(e){alert('Failed to send: '+e.message);}});
  clearBtn.addEventListener('click',async()=>{if(!chatRoomId)return;const userMsgElements=document.querySelectorAll('.chat-msg.user .chat-clear-btn[data-msgid]');for(const el of userMsgElements){await apiCall('delete_chat_message',{message_id:el.dataset.msgid});}loadMessages();});
  function startPolling(){if(chatPollInterval)clearInterval(chatPollInterval);chatPollInterval=setInterval(loadMessages,3000);}
  async function updatePresence(){try{const data=await apiCall('check_admin_online');adminDot.className='admin-dot '+(data?.online?'online':'offline');}catch(e){}}
  updatePresence();setInterval(updatePresence,15000);
  window.addEventListener('beforeunload',()=>{if(chatPollInterval)clearInterval(chatPollInterval);});
  function pingUserPresence(){if(localStorage.getItem('sb-token'))apiCall('update_user_presence').catch(()=>{});}
  setInterval(pingUserPresence,30000);pingUserPresence();
})();
