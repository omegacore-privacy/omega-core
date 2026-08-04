# Omega Core — Server backend

Server Node.js che fa da relay per la chat di Omega Core: WebSocket per i
messaggi (pubblici e privati), Express per servire il sito statico.

## Avvio rapido

```bash
npm install
cp .env.example .env
npm run gen-admin-hash      # scegli la risposta segreta admin, es. "colleAdmin"
# incolla l'hash stampato dentro .env come ADMIN_ANSWER_HASH
npm start
```

Il sito sarà su `http://localhost:8787` (o la porta che imposti in `.env`).

## Cosa fa davvero questo server

- **Relay, non lettore**: i messaggi (`ciphertext`) arrivano già cifrati
  end-to-end dal client (vedi `omega-core.html`, che genera le chiavi con
  la Web Crypto API). Il server li inoltra senza mai decifrarli né
  salvarli su disco.
- **IP mai inoltrato**: l'indirizzo IP del client è noto al server (serve
  per il rate-limiting) ma non compare mai in nessun messaggio inviato
  agli altri utenti — chat pubblica o privata.
- **Anti-DDoS applicativo** (`src/rateLimiter.js`):
  - limite di connessioni simultanee per IP;
  - limite di nuove connessioni per finestra temporale;
  - token bucket per utente sui messaggi (burst + velocità sostenuta);
  - limite dimensione payload WebSocket (`maxPayload`).
  
  **Importante**: questo è un livello di mitigazione applicativo. Un vero
  DDoS volumetrico va fermato a livello di rete/infrastruttura (reverse
  proxy, CDN, firewall) — non solo dentro Node.js.
- **Anti-XSS lato server** (`src/sanitize.js`): nomi utente e messaggi di
  sistema vengono ripuliti (niente tag HTML) prima di essere ritrasmessi,
  come difesa aggiuntiva rispetto all'escaping già fatto dal client.
- **Admin a domanda segreta** (`src/admin.js`): la risposta corretta non è
  mai nel codice in chiaro, solo il suo hash bcrypt in `.env`. Ogni socket
  ha un numero massimo di tentativi prima della disconnessione forzata.

## Protocollo WebSocket (JSON su singola connessione)

Client → Server:

| type              | campi                    | note |
|-------------------|---------------------------|------|
| `join`             | `name`                    | il nome viene sanificato; se già in uso viene reso univoco |
| `public_message`   | `ciphertext`               | blob cifrato dal client, inoltrato a tutti |
| `private_message`  | `to`, `ciphertext`         | inoltrato solo al destinatario |
| `admin_auth`       | `answer`                   | risposta alla domanda segreta |
| `admin_stats`      | —                          | richiede `isAdmin` lato server |

Server → Client:

| type                  | campi |
|-----------------------|-------|
| `welcome`              | `sessionId` |
| `joined`                | `name` |
| `system`                | `text` |
| `presence`              | `users` |
| `public_message`        | `from`, `ciphertext`, `ts` |
| `private_message`       | `from`, `ciphertext`, `ts` |
| `admin_auth_result`     | `ok`, `reason?` |
| `admin_stats_result`    | `connectedUsers`, `uptimeSec` |
| `error`                 | `code`, `message` |

## Prossimo passo

Il file `public/index.html` (la UI) al momento usa dati simulati in
locale. Il prossimo pezzo è collegare il suo JS a questo WebSocket
(sostituendo `sendMessage`/`seedChat` con chiamate reali al protocollo
sopra) — lo facciamo quando vuoi procedere con quell'integrazione.

## Sicurezza — cose da fare prima di andare online sul serio

- Metti il server dietro HTTPS/WSS (es. reverse proxy con certificato).
- Se usi un proxy, imposta `app.set('trust proxy', ...)` e leggi l'IP da
  `X-Forwarded-For` **solo** se il proxy è fidato.
- Valuta un vero livello anti-DDoS di rete (Cloudflare o simili) davanti
  al server, il rate-limiting qui dentro è solo la seconda linea.
- Ruota/rigenera `ADMIN_ANSWER_HASH` periodicamente.
