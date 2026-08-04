/**
 * Sanificazione lato server — difesa "in profondità".
 * Il client fa già escaping prima di mostrare a schermo, ma non ci
 * fidiamo mai solo del client: ogni stringa che il server accetta
 * ed eventualmente re-invia ad altri utenti (nomi, messaggi di
 * sistema, metadati) viene ripulita anche qui.
 */

const HTML_ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHTML(str) {
  return String(str).replace(/[&<>"']/g, ch => HTML_ESCAPE_MAP[ch]);
}

// Nome utente: solo caratteri "innocui", lunghezza limitata.
function sanitizeName(raw) {
  if (typeof raw !== 'string') return 'Anonimo';
  const cleaned = raw
    .replace(/<[^>]*>/g, '')   // rimuove tag
    .replace(/[^\p{L}\p{N}_\- ]/gu, '') // solo lettere/numeri/spazi/_/-
    .trim()
    .slice(0, 24);
  return cleaned.length ? cleaned : 'Anonimo';
}

// Testo libero (messaggi non cifrati, es. messaggi di sistema): escaping + limite lunghezza.
function sanitizeText(raw, maxLen = 2000) {
  if (typeof raw !== 'string') return '';
  return escapeHTML(raw).slice(0, maxLen);
}

// Per i blob cifrati (payload E2E) il server non deve MAI provare a
// interpretarli come testo: li tratta come dati opachi, controlla solo
// che siano stringhe base64-like entro una lunghezza massima ragionevole.
function isValidCiphertextBlob(raw, maxLen = 20000) {
  return typeof raw === 'string' && raw.length > 0 && raw.length <= maxLen && /^[A-Za-z0-9+/=_-]+$/.test(raw);
}

module.exports = { escapeHTML, sanitizeName, sanitizeText, isValidCiphertextBlob };
