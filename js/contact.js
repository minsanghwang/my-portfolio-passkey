/* =========================================================
  contact.js
  - 이메일 주소를 HTML에 평문으로 두지 않고, 조각내서 보관합니다.
  - 버튼을 눌렀을 때만 조립해서 화면에 표시합니다(다시 누르면 가려짐).
  - 주의: 이건 "봇의 자동 수집"을 어렵게 만드는 수준의 눈속임이며,
    비밀번호/토큰처럼 진짜 지켜야 하는 값에 쓰는 방식이 아닙니다.
    (클릭하면 사람 눈에는 보이는 값이므로 완전한 보안은 아닙니다.)

  ===== 여기만 수정하세요 =====
  아래 EMAIL_USER / EMAIL_DOMAIN 값을 본인 이메일로 바꾸세요.
  예) hello@example.com  ->  EMAIL_USER: 'hello', EMAIL_DOMAIN: 'example.com'
============================================================ */
const CONTACT_CONFIG = {
  EMAIL_USER: 'kbhj6789',
  EMAIL_DOMAIN: 'gmail.com',
};

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('revealEmailBtn');
  const out = document.getElementById('emailRevealed');
  if (!btn || !out) return;

  let revealed = false;

  btn.addEventListener('click', () => {
    revealed = !revealed;

    if (revealed) {
      const address = `${CONTACT_CONFIG.EMAIL_USER}@${CONTACT_CONFIG.EMAIL_DOMAIN}`;
      out.textContent = address;
      btn.textContent = '이메일 주소 가리기';
      btn.setAttribute('aria-expanded', 'true');
    } else {
      out.textContent = '';
      btn.textContent = '이메일 주소 보기';
      btn.setAttribute('aria-expanded', 'false');
    }
  });
});
