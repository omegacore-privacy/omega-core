/**
 * Autenticazione admin tramite "domanda segreta".
 *
 * La risposta corretta NON è mai salvata in chiaro: nel file .env
 * teniamo solo ADMIN_ANSWER_HASH, un hash bcrypt generato con
 * `npm run gen-admin-hash`. Il confronto avviene con bcrypt.compare,
 * che è resistente a timing attack banali, e ogni socket ha un
 * numero massimo di tentativi prima di essere disconnessa.
 */

const bcrypt = require('bcryptjs');

const MAX_ATTEMPTS_PER_CONNECTION = 5;

async function verifyAdminAnswer(answer, answerHash) {
  if (!answerHash) return false; // nessun hash configurato -> admin disabilitato
  if (typeof answer !== 'string' || answer.length === 0 || answer.length > 100) return false;
  try {
    return await bcrypt.compare(answer.trim().toLowerCase(), answerHash);
  } catch {
    return false;
  }
}

module.exports = { verifyAdminAnswer, MAX_ATTEMPTS_PER_CONNECTION };
