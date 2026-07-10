import DOMPurify from 'dompurify';

export function sanitizeHtml(str) {
  return DOMPurify.sanitize(String(str));
}

// If the goal is plain text escaping for HTML text nodes:
const blocked = new Set(['__proto__', 'prototype', 'constructor']);

function safeGet(obj, path) {
  let result = Object.create(null);
  for (const part of path.split('.')) {
    if (blocked.has(part) || result == null || !Object.prototype.hasOwnProperty.call(obj, part)) {
      return undefined;
    }
    result = obj[part];
  }
  return result;
}

export function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}