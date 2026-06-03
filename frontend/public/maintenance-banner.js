/**
 * CyberShield — Maintenance Notice Banner
 * 
 * DEPLOYMENT:
 * 1. Save this file as frontend/public/maintenance-banner.js
 * 2. Add this ONE line inside the <head> tag of these files:
 *      - index.html
 *      - dashboard.html
 *      - register.html
 *    
 *    <script src="/maintenance-banner.js"></script>
 *
 * 3. git add -A && git commit -m "add: maintenance notice banner" && git push
 * 4. Done — Vercel auto-deploys in ~30 seconds.
 *
 * To remove the banner later: delete the <script> tag from each page and redeploy.
 */

(function () {
  const banner = document.createElement('div');
  banner.id = 'maintenance-banner';
  banner.innerHTML = `
    <span style="font-size:16px;margin-right:8px;">🔧</span>
    <span>
      <strong>Demo Mode — Backend Offline</strong>
      &nbsp;·&nbsp;
      The scan engine (Railway) and database (Supabase) are currently paused.
      Scans will return an error. This project is preserved for portfolio purposes.
      &nbsp;
      <a href="https://jihun.me/cybershield.html" target="_blank" style="color:#2dd4bf;text-decoration:underline;font-weight:600;">
        View full write-up →
      </a>
    </span>
    <button onclick="document.getElementById('maintenance-banner').style.display='none'"
      style="margin-left:auto;background:none;border:none;color:#8b949e;cursor:pointer;font-size:18px;line-height:1;padding:0 4px;flex-shrink:0;">
      ×
    </button>
  `;

  Object.assign(banner.style, {
    position:       'fixed',
    top:            '0',
    left:           '0',
    right:          '0',
    zIndex:         '99999',
    display:        'flex',
    alignItems:     'center',
    gap:            '8px',
    padding:        '10px 20px',
    background:     '#161b22',
    borderBottom:   '1px solid #30363d',
    color:          '#e6edf3',
    fontFamily:     'Inter, -apple-system, sans-serif',
    fontSize:       '13px',
    lineHeight:     '1.5',
    boxSizing:      'border-box',
  });

  // Push page content down so banner doesn't overlap nav
  function applyOffset() {
    const h = banner.offsetHeight;
    document.body.style.paddingTop = h + 'px';
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.body.insertBefore(banner, document.body.firstChild);
    applyOffset();
    window.addEventListener('resize', applyOffset);
  });
})();
