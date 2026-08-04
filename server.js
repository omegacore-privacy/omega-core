require('dotenv').config();
const express = require('express');
const http = require('http');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const { TokenBucket, ConnectionGuard } = require('./src/rateLimiter');
const { sanitizeName, sanitizeText, isValidCiphertextBlob } = require('./src/sanitize');
const { verifyAdminAnswer, MAX_ATTEMPTS_PER_CONNECTION } = require('./src/admin');

const PORT = process.env.PORT || 8787;
const ADMIN_ANSWER_HASH = process.env.ADMIN_ANSWER_HASH || null;
const MAX_MESSAGE_BYTES = 8 * 1024; // limite payload per messaggio WS (anti-DDoS)

/* ===================== HTTP layer ===================== */
const app = express();
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false // il sito è servito come statico: se aggiungi una CSP, aggiornala qui
}));

// Rate limit sulle richieste HTTP "normali" (statico + health check).
// Nota: mitiga abusi a livello applicativo, NON sostituisce protezioni
// di rete/CDN per DDoS volumetrici veri.
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => {
  res.json({ ok: true, connections: wss ? wss.clients.size : 0, uptimeSec: Math.floor(process.uptime()) });
});

const server = http.createServer(app);

/* ===================== WebSocket layer ===================== */
const wss = new WebSocketServer({ server, maxPayload: MAX_MESSAGE_BYTES });

const connGuard = new ConnectionGuard({
  maxConnectionsPerIp: 8,
  maxNewConnectionsPerWindow: 20,
  windowMs: 10_000,
});

// sessionId -> { ws, name, isAdmin, ip, bucket, adminAttempts }
const sessions = new Map();

function getClientIp(req) {
  // Dietro un reverse proxy, imposta trust proxy e leggi X-Forwarded-For lì,
  // non qui: falsificare questo header è banale se non sei dietro un proxy fidato.
  return req.socket.remoteAddress || 'unknown';
}

// Invia un oggetto JSON a una socket, senza MAI includere l'IP del mittente.
function send(ws, payload) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
}

function broadcastPublic(payload, exceptSessionId = null) {
  for (const [sid, s] of sessions) {
    if (sid === exceptSessionId) continue;
    send(s.ws, payload);
  }
}

function findSessionByName(name) {
  for (const [sid, s] of sessions) {
    if (s.name === name) return { sid, s };
  }
  return null;
}

function publicPresenceList() {
  // Includiamo la chiave pubblica (dato non sensibile, serve ai peer per
  // derivare la chiave condivisa E2E) ma MAI l'IP.
  return Array.from(sessions.values()).map(s => ({ name: s.name, isAdmin: s.isAdmin, pubkey: s.pubkey || null }));
}

wss.on('connection', (ws, req) => {
  const ip = getClientIp(req);

  const gate = connGuard.canConnect(ip);
  if (!gate.ok) {
    send(ws, { type: 'error', code: gate.reason, message: 'Troppe connessioni. Riprova più tardi.' });
    ws.close(1013, gate.reason); // 1013 = Try Again Later
    return;
  }
  connGuard.registerConnect(ip);

  const sessionId = uuidv4();
  const session = {
    ws,
    ip,                 // usata SOLO server-side per rate limiting, mai inoltrata ad altri client
    name: null,
    isAdmin: false,
    adminAttempts: 0,
    joinedAt: Date.now(),
    msgBucket: new TokenBucket({ capacity: 8, refillPerSecond: 1.5 }), // ~8 msg di burst, poi ~1.5/s
  };
  sessions.set(sessionId, session);

  send(ws, { type: 'welcome', sessionId });

  ws.on('message', async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return; // JSON malformato: ignorato silenziosamente
    }

    if (typeof msg !== 'object' || !msg.type) return;

    switch (msg.type) {
      /* ---- Ingresso: il client sceglie/riceve un chiave pubblica e un nome ---- */
      case 'join': {
        const name = sanitizeName(msg.name);
        session.name = findSessionByName(name) ? `${name}_${sessionId.slice(0, 4)}` : name;
        // Chiave pubblica ECDH (raw, base64), usata dai peer per l'E2E dei DM.
        // Non è un dato segreto: validiamo solo forma/lunghezza, mai il contenuto.
        session.pubkey = isValidCiphertextBlob(msg.pubkey, 300) ? msg.pubkey : null;
        broadcastPublic({ type: 'system', text: sanitizeText(`${session.name} è entrato nel nodo.`) }, sessionId);
        broadcastPublic({ type: 'presence', users: publicPresenceList() });
        send(ws, { type: 'joined', name: session.name });
        break;
      }

      /* ---- Messaggio pubblico: payload già cifrato E2E dal client ---- */
      case 'public_message': {
        if (!session.name) return;
        if (!session.msgBucket.tryConsume()) {
          send(ws, { type: 'error', code: 'rate_limited', message: 'Stai inviando messaggi troppo velocemente.' });
          return;
        }
        if (!isValidCiphertextBlob(msg.ciphertext)) {
          send(ws, { type: 'error', code: 'invalid_payload', message: 'Payload non valido.' });
          return;
        }
        // Il server fa solo da relay: non decifra, non salva il testo in chiaro.
        broadcastPublic({
          type: 'public_message',
          from: session.name,
          ciphertext: msg.ciphertext,
          ts: Date.now(),
        }, sessionId);
        break;
      }

      /* ---- Messaggio privato: instradato solo al destinatario, mai con IP ---- */
      case 'private_message': {
        if (!session.name) return;
        if (!session.msgBucket.tryConsume()) {
          send(ws, { type: 'error', code: 'rate_limited', message: 'Stai inviando messaggi troppo velocemente.' });
          return;
        }
        if (!isValidCiphertextBlob(msg.ciphertext)) return;
        const target = findSessionByName(sanitizeName(msg.to || ''));
        if (!target) {
          send(ws, { type: 'error', code: 'user_not_found', message: 'Destinatario non connesso.' });
          return;
        }
        send(target.s.ws, {
          type: 'private_message',
          from: session.name,
          ciphertext: msg.ciphertext,
          ts: Date.now(),
        });
        break;
      }

      /* ---- Autenticazione admin tramite domanda segreta ---- */
      case 'admin_auth': {
        session.adminAttempts++;
        if (session.adminAttempts > MAX_ATTEMPTS_PER_CONNECTION) {
          send(ws, { type: 'admin_auth_result', ok: false, reason: 'too_many_attempts' });
          ws.close(1008, 'too_many_admin_attempts'); // chiude la connessione: mitiga il bruteforce
          return;
        }
        const ok = await verifyAdminAnswer(msg.answer, ADMIN_ANSWER_HASH);
        if (ok) {
          session.isAdmin = true;
          send(ws, { type: 'admin_auth_result', ok: true });
          if (session.name) broadcastPublic({ type: 'presence', users: publicPresenceList() });
        } else {
          send(ws, { type: 'admin_auth_result', ok: false, reason: 'wrong_answer' });
        }
        break;
      }

      /* ---- Statistiche pannello admin ---- */
      case 'admin_stats': {
        if (!session.isAdmin) {
          send(ws, { type: 'error', code: 'forbidden', message: 'Non autorizzato.' });
          return;
        }
        send(ws, {
          type: 'admin_stats_result',
          connectedUsers: sessions.size,
          uptimeSec: Math.floor(process.uptime()),
        });
        break;
      }

      default:
        break; // tipo di messaggio sconosciuto: ignorato
    }
  });

  ws.on('close', () => {
    connGuard.registerDisconnect(ip);
    sessions.delete(sessionId);
    if (session.name) {
      broadcastPublic({ type: 'system', text: sanitizeText(`${session.name} ha lasciato il nodo.`) });
      broadcastPublic({ type: 'presence', users: publicPresenceList() });
    }
  });

  ws.on('error', () => {
    // connessione già gestita da 'close'; qui evitiamo solo che un errore non gestito crashi il processo
  });
});

server.listen(PORT, () => {
  console.log(`Omega Core server in ascolto su http://localhost:${PORT}`);
  if (!ADMIN_ANSWER_HASH) {
    console.warn('ATTENZIONE: ADMIN_ANSWER_HASH non impostato in .env — il login admin è disabilitato. Esegui "npm run gen-admin-hash".');
  }
});
