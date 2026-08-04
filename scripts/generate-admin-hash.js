/**
 * Uso: npm run gen-admin-hash
 * Chiede la risposta segreta admin e stampa l'hash bcrypt da
 * incollare in .env come ADMIN_ANSWER_HASH. La risposta in chiaro
 * non viene mai scritta su disco da questo script.
 */
const bcrypt = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Risposta segreta admin (es. colleAdmin): ', async (answer) => {
  const normalized = answer.trim().toLowerCase();
  const hash = await bcrypt.hash(normalized, 12);
  console.log('\nAggiungi questa riga al tuo file .env:\n');
  console.log(`ADMIN_ANSWER_HASH=${hash}\n`);
  rl.close();
});
