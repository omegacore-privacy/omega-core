/**
 * Rate limiting "a livello applicativo".
 *
 * Attenzione: questo NON sostituisce una protezione anti-DDoS vera
 * (che va fatta a livello di rete/infrastruttura: reverse proxy,
 * Cloudflare, firewall, ecc.). Qui mitighiamo solo l'abuso a livello
 * di applicazione: troppi messaggi, troppe connessioni dalla stessa IP,
 * payload troppo grandi, tentativi di login admin ripetuti.
 */

class TokenBucket {
  constructor({ capacity, refillPerSecond }) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillPerSecond = refillPerSecond;
    this.lastRefill = Date.now();
  }

  _refill() {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.refillPerSecond);
    this.lastRefill = now;
  }

  tryConsume(cost = 1) {
    this._refill();
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }
}

/**
 * Tiene traccia di quante connessioni WebSocket attive provengono
 * dalla stessa IP, e quante nuove connessioni arrivano in una finestra
 * di tempo (mitiga i tentativi di saturare il server con tante socket).
 */
class ConnectionGuard {
  constructor({ maxConnectionsPerIp = 8, maxNewConnectionsPerWindow = 20, windowMs = 10_000 } = {}) {
    this.maxConnectionsPerIp = maxConnectionsPerIp;
    this.maxNewConnectionsPerWindow = maxNewConnectionsPerWindow;
    this.windowMs = windowMs;
    this.activeByIp = new Map();      // ip -> count connessioni attive
    this.recentJoinsByIp = new Map(); // ip -> [timestamps]
  }

  canConnect(ip) {
    const active = this.activeByIp.get(ip) || 0;
    if (active >= this.maxConnectionsPerIp) return { ok: false, reason: 'too_many_connections' };

    const now = Date.now();
    const joins = (this.recentJoinsByIp.get(ip) || []).filter(t => now - t < this.windowMs);
    if (joins.length >= this.maxNewConnectionsPerWindow) return { ok: false, reason: 'connection_flood' };

    joins.push(now);
    this.recentJoinsByIp.set(ip, joins);
    return { ok: true };
  }

  registerConnect(ip) {
    this.activeByIp.set(ip, (this.activeByIp.get(ip) || 0) + 1);
  }

  registerDisconnect(ip) {
    const n = (this.activeByIp.get(ip) || 1) - 1;
    if (n <= 0) this.activeByIp.delete(ip);
    else this.activeByIp.set(ip, n);
  }
}

module.exports = { TokenBucket, ConnectionGuard };
