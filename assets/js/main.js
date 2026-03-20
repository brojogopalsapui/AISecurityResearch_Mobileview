
document.addEventListener('DOMContentLoaded', () => {
  const nav = document.querySelector('.nav');
  const btn = document.querySelector('.menu-btn');

  if (btn && !btn.querySelector('span')) {
    btn.innerHTML = '<span></span><span></span><span></span>';
  }

  if (btn && nav) {
    if (!nav.id) nav.id = 'siteNav';
    btn.setAttribute('aria-controls', nav.id);
    btn.setAttribute('aria-expanded', 'false');

    const closeMenu = () => {
      nav.classList.remove('open');
      btn.classList.remove('active');
      btn.setAttribute('aria-expanded', 'false');
    };

    const toggleMenu = () => {
      const open = nav.classList.toggle('open');
      btn.classList.toggle('active', open);
      btn.setAttribute('aria-expanded', String(open));
    };

    btn.addEventListener('click', (event) => {
      event.stopPropagation();
      toggleMenu();
    });

    document.addEventListener('click', (event) => {
      if (window.innerWidth <= 860 && !nav.contains(event.target) && !btn.contains(event.target)) {
        closeMenu();
      }
    });

    nav.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        if (window.innerWidth <= 860) closeMenu();
      });
    });

    window.addEventListener('resize', () => {
      if (window.innerWidth > 860) closeMenu();
    });
  }

  const expandButtons = document.querySelectorAll('.img-expand-btn');
  const zoomableImages = document.querySelectorAll('.zoom-img');

  if (expandButtons.length || zoomableImages.length) {
    const overlay = document.createElement('div');
    overlay.className = 'image-lightbox';
    overlay.innerHTML = `
      <div class="image-lightbox__dialog" role="dialog" aria-modal="true" aria-label="Expanded image view">
        <button class="image-lightbox__close" type="button" aria-label="Close expanded image">×</button>
        <img class="image-lightbox__img" src="" alt="" />
      </div>
    `;

    document.body.appendChild(overlay);

    const overlayImg = overlay.querySelector('.image-lightbox__img');
    const closeBtn = overlay.querySelector('.image-lightbox__close');

    const openLightbox = (src, alt = '') => {
      overlayImg.src = src;
      overlayImg.alt = alt;
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    };

    const closeLightbox = () => {
      overlay.classList.remove('open');
      overlayImg.src = '';
      overlayImg.alt = '';
      document.body.style.overflow = '';
    };

    expandButtons.forEach((button) => {
      button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        openLightbox(button.getAttribute('data-full'), button.getAttribute('data-alt') || '');
      });
    });

    zoomableImages.forEach((img) => {
      img.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        openLightbox(img.currentSrc || img.src, img.alt || '');
      });
    });

    closeBtn.addEventListener('click', closeLightbox);
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) closeLightbox();
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && overlay.classList.contains('open')) closeLightbox();
    });
  }
});
