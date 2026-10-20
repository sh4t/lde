import { renderRuns, renderRunDetail } from '/js/runs.js';
import { renderSettings } from '/js/settings.js';
import { renderPackageSearch } from '/js/package_search.js';

const root = document.getElementById('app');

const routes = [
  { pattern: /^\/runs\/([a-f0-9]+)$/, handler: (m) => renderRunDetail(root, m[1]) },
  { pattern: /^\/runs$/, handler: () => renderRuns(root) },
  { pattern: /^\/package-search$/, handler: () => renderPackageSearch(root) },
  { pattern: /^\/settings$/, handler: () => renderSettings(root) },
  { pattern: /^\/$/, handler: () => navigate('/package-search') },
];

function dispatch() {
  const path = window.location.pathname || '/';
  for (const link of document.querySelectorAll('header nav a')) {
    link.classList.toggle('active', path.startsWith(link.getAttribute('href')));
  }
  for (const { pattern, handler } of routes) {
    const m = path.match(pattern);
    if (m) {
      try { handler(m); } catch (err) {
        root.innerHTML = `<div class="card"><h2>Error</h2><pre class="log">${escapeHtml(err.message)}</pre></div>`;
      }
      return;
    }
  }
  // The path comes from the address bar, so it is attacker-chosen text.
  root.innerHTML = `<div class="card"><h2>Not found</h2><p class="muted">${escapeHtml(path)}</p></div>`;
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

export function navigate(path) {
  window.history.pushState({}, '', path);
  dispatch();
}

document.addEventListener('click', (event) => {
  const anchor = event.target.closest('a[data-route]');
  if (!anchor) return;
  event.preventDefault();
  navigate(anchor.getAttribute('href'));
});

window.addEventListener('popstate', dispatch);
dispatch();
