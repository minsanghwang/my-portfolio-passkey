document.addEventListener('DOMContentLoaded', () => {
  /* ---------- 모바일 내비게이션 토글 (마우스 클릭 + 키보드 Enter/Space) ---------- */
  const navToggle = document.getElementById('navToggle');
  const primaryNav = document.getElementById('primaryNav');

  if (navToggle && primaryNav) {
    navToggle.addEventListener('click', () => {
      const isOpen = primaryNav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', String(isOpen));
    });

    // 메뉴 항목을 고르면 자동으로 닫기 (모바일에서 다음 조작 편하게)
    primaryNav.querySelectorAll('.nav-link').forEach((link) => {
      link.addEventListener('click', () => {
        primaryNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
      });
    });

    // 메뉴 밖을 클릭하면 닫기
    document.addEventListener('click', (e) => {
      if (!primaryNav.classList.contains('is-open')) return;
      const clickedInside = primaryNav.contains(e.target) || navToggle.contains(e.target);
      if (!clickedInside) {
        primaryNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
      }
    });

    // Esc로 닫기 (키보드 사용자 배려)
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && primaryNav.classList.contains('is-open')) {
        primaryNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.focus();
      }
    });
  }

  /* ---------- 프로젝트 필터 (마우스 클릭 + 키보드 Tab/Enter) ---------- */
  const filterBtns = document.querySelectorAll('.filter-btn');
  const projectCards = document.querySelectorAll('.project-card');
  const emptyMsg = document.getElementById('filterEmpty');

  filterBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      filterBtns.forEach((b) => b.classList.remove('is-active'));
      btn.classList.add('is-active');

      const filter = btn.dataset.filter;
      let visibleCount = 0;

      projectCards.forEach((card) => {
        const match = filter === 'all' || card.dataset.category === filter;
        card.hidden = !match;
        if (match) visibleCount += 1;
      });

      if (emptyMsg) emptyMsg.hidden = visibleCount !== 0;
    });
  });

  /* ---------- 프로젝트 카드: 키보드로도 hover와 동일한 강조 상태 ---------- */
  projectCards.forEach((card) => {
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        card.classList.toggle('is-focused-open');
      }
    });
  });

  /* ---------- 핵심 소개문구 3개 아코디언 (마우스 클릭 + 키보드 Enter/Space) ---------- */
  /* button 요소는 Enter/Space를 누르면 브라우저가 자동으로 click 이벤트를 발생시키므로
     별도의 keydown 처리 없이도 키보드로 펼치고 접을 수 있습니다. */
  const accordionTriggers = document.querySelectorAll('.accordion-trigger');
  accordionTriggers.forEach((btn) => {
    const panel = document.getElementById(btn.getAttribute('aria-controls'));
    btn.addEventListener('click', () => {
      const isExpanded = btn.getAttribute('aria-expanded') === 'true';
      btn.setAttribute('aria-expanded', String(!isExpanded));
      if (panel) {
        panel.classList.toggle('is-open', !isExpanded);
        panel.setAttribute('aria-hidden', String(isExpanded));
      }
    });
  });

  /* ---------- 맨 위로 이동 ---------- */
  const backToTop = document.getElementById('backToTop');
  if (backToTop) {
    backToTop.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  /* ---------- 푸터 연도 자동 갱신 ---------- */
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());
});
