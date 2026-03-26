(function(){
  function initMenu(){
    const btn = document.getElementById('shellMenuBtn');
    const nav = document.getElementById('shellNav');
    if (!btn || !nav) return;
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = nav.classList.toggle('open');
      btn.classList.toggle('active', open);
      btn.setAttribute('aria-expanded', String(open));
      document.body.classList.toggle('nav-open', open);
    });
    document.addEventListener('click', (e) => {
      if (!nav.classList.contains('open')) return;
      if (!nav.contains(e.target) && !btn.contains(e.target)) {
        nav.classList.remove('open');
        btn.classList.remove('active');
        btn.setAttribute('aria-expanded', 'false');
        document.body.classList.remove('nav-open');
      }
    });
  }

  function initLightbox(){
    const targets = document.querySelectorAll('.zoom-img, .zoomable-thumb, .hero-figure-img, .feature-media img, .portal-media img');
    if (!targets.length) return;
    const overlay = document.createElement('div');
    overlay.className = 'portal-lightbox';
    overlay.innerHTML = `
      <div class="portal-lightbox__dialog" role="dialog" aria-modal="true" aria-label="Expanded image view">
        <button class="portal-lightbox__close" type="button" aria-label="Close expanded image">×</button>
        <img class="portal-lightbox__img" src="" alt="" />
      </div>`;
    document.body.appendChild(overlay);
    const img = overlay.querySelector('.portal-lightbox__img');
    const closeBtn = overlay.querySelector('.portal-lightbox__close');
    const close = () => {
      overlay.classList.remove('open');
      document.body.style.overflow = '';
      img.src = '';
      img.alt = '';
    };
    const open = (src, alt='') => {
      img.src = src;
      img.alt = alt;
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    };
    targets.forEach(target => {
      target.addEventListener('click', (e) => {
        if (target.closest('a') && target.closest('a').getAttribute('href')?.endsWith('.html')) return;
        e.preventDefault();
        e.stopPropagation();
        open(target.currentSrc || target.src, target.alt || 'Expanded image');
      });
    });
    closeBtn.addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  }

  function initReveal(){
    const nodes = document.querySelectorAll('main > section, .content-card, .post-card, .topic-card, .section-card, .panel, .feature-card, .quick-card, .pulse-card, .profile-card');
    nodes.forEach(el => el.classList.add('portal-reveal'));
    const io = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });
    nodes.forEach(el => io.observe(el));
  }

  function initJumpRail(){
    const toc = document.querySelector('.toc');
    const hero = document.querySelector('.page-hero, .hero');
    if (!toc || !hero) return;
    const links = Array.from(toc.querySelectorAll('a[href^="#"]')).slice(0, 8);
    if (!links.length) return;
    const rail = document.createElement('nav');
    rail.className = 'portal-chip-rail';
    rail.setAttribute('aria-label', 'Quick section links');
    rail.innerHTML = links.map(a => `<a href="${a.getAttribute('href')}">${a.textContent.trim()}</a>`).join('');
    hero.insertAdjacentElement('afterend', rail);
  }

  function initCollapsibleCards(){
    const cards = document.querySelectorAll('.content-card, .panel');
    cards.forEach((card, index) => {
      if (card.closest('.page-hero') || card.closest('.cta-band') || card.closest('.site-shell-footer') || card.classList.contains('portal-skip-collapse')) return;
      const children = Array.from(card.children).filter(el => el.nodeType === 1 && !['BUTTON'].includes(el.tagName));
      const textLength = (card.textContent || '').trim().length;
      if (children.length < 4 || textLength < 850) return;
      const wrap = document.createElement('div');
      wrap.className = 'portal-collapse';
      const keep = 3;
      children.slice(keep).forEach(node => wrap.appendChild(node));
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'portal-toggle';
      btn.setAttribute('aria-expanded', 'false');
      btn.innerHTML = '<span>View full note</span><strong>+</strong>';
      btn.addEventListener('click', () => {
        const open = card.classList.toggle('is-open');
        btn.setAttribute('aria-expanded', String(open));
        btn.innerHTML = open ? '<span>Hide extra detail</span><strong>−</strong>' : '<span>View full note</span><strong>+</strong>';
      });
      card.appendChild(wrap);
      card.appendChild(btn);
    });
  }

  function initTilt(){
    if (window.matchMedia('(pointer: coarse)').matches) return;
    const cards = document.querySelectorAll('.quick-card, .feature-card, .content-card, .panel, .post-card, .section-card, .topic-card, .foundation-card, .profile-card, .pulse-card');
    cards.forEach(card => {
      card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const px = (e.clientX - rect.left) / rect.width;
        const py = (e.clientY - rect.top) / rect.height;
        const rx = (0.5 - py) * 6;
        const ry = (px - 0.5) * 8;
        card.style.transform = `perspective(900px) rotateX(${rx}deg) rotateY(${ry}deg) translateY(-4px)`;
      });
      card.addEventListener('mouseleave', () => { card.style.transform = ''; });
    });
  }

  function enhanceExternalLinks(){
    document.querySelectorAll('main a[href^="http"]').forEach(a => {
      if (!a.target) a.target = '_blank';
      a.rel = a.rel || 'noopener noreferrer';
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initMenu();
    initLightbox();
    initReveal();
    initJumpRail();
    initCollapsibleCards();
    initTilt();
    enhanceExternalLinks();
  });
})();
