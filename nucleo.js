// Núcleo del visor (R-039, R-040): descifrado y valoración. Sin DOM, para probarlo también con Node.
(function (raiz) {
  "use strict";

  const VERSION = 1;

  function deB64url(texto) {
    const b64 = texto.trim().replace(/-/g, "+").replace(/_/g, "/");
    const relleno = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(relleno);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function importarClave(claveB64) {
    const cruda = deB64url(claveB64);
    if (cruda.length !== 32) throw new Error("La clave no tiene 32 bytes");
    return crypto.subtle.importKey("raw", cruda, { name: "AES-GCM" }, false, ["decrypt"]);
  }

  // Devuelve la foto o lanza si no es auténtica, es de otra corrida o de otra versión.
  async function descifrar(clave, corrida, mensaje) {
    const crudo = deB64url(mensaje);
    const aad = new TextEncoder().encode(`visor-v${VERSION}|${corrida}`);
    const claro = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: crudo.slice(0, 12), additionalData: aad }, clave, crudo.slice(12));
    const foto = JSON.parse(new TextDecoder().decode(claro));
    if (foto.v !== VERSION || foto.corrida !== corrida || !Number.isInteger(foto.seq)) {
      throw new Error("Foto de otra versión o corrida");
    }
    return foto;
  }

  const FUTURO_MS = 5 * 60000;     // tolerancia de reloj: una foto «del futuro» más allá de esto es inválida

  // De los mensajes de ntfy (JSON por renglón) se queda con la foto válida de mayor seq. La corrida esperada viene
  // de la configuración del celular, nunca del mensaje.
  async function mejorFoto(clave, corrida, textoNtfy, ahora = Date.now()) {
    let mejor = null, invalidas = 0;
    for (const renglon of textoNtfy.split("\n")) {
      if (!renglon.trim()) continue;
      let m;
      try { m = JSON.parse(renglon); } catch (e) { continue; }
      if (m.event !== "message" || typeof m.message !== "string") continue;
      try {
        const f = await descifrar(clave, corrida, m.message);
        if (!Number.isFinite(f.emitido_ms) || f.emitido_ms > ahora + FUTURO_MS) throw new Error("Hora inválida");
        if (!mejor || f.seq > mejor.seq) mejor = f;
      } catch (e) { invalidas++; }
    }
    return { foto: mejor, invalidas };
  }

  // Valoración con la fórmula del motor: C = efectivo + Σ(margen + q·(precio − entrada)).
  // `precios` mapea símbolo -> precio en vivo; si falta, se usa la marca de referencia de la foto.
  function valorar(foto, precios) {
    let capital = Number(foto.efectivo), noRealizada = 0, todasEnVivo = true;
    const posiciones = foto.posiciones.map((p) => {
      const q = Number(p.q), entrada = Number(p.entrada), margen = Number(p.margen);
      const stop = p.stop === null ? null : Number(p.stop);
      let precio = precios[p.s], enVivo = true;
      if (precio === undefined) {
        enVivo = false; todasEnVivo = false;
        precio = p.marca_ref === null ? null : Number(p.marca_ref);
      }
      if (precio === null) { todasEnVivo = false; return { ...p, precio: null, enVivo: false }; }
      const resultado = q * (precio - entrada);
      noRealizada += resultado;
      capital += margen + resultado;
      const recorrido = stop === null ? 0 : Math.min(1, Math.max(0, (entrada - precio) / (entrada - stop)));
      return {
        ...p, precio, enVivo, resultado, pct: precio / entrada - 1,
        aStop: stop === null ? null : stop / precio - 1, recorrido,
      };
    });
    const valuable = posiciones.every((p) => p.precio !== null);
    const acu = foto.acumulado;
    const desdeArranque = valuable ? {
      total: capital - Number(foto.capital_inicial),
      realizado: Number(acu.realizado), comisiones: -Number(acu.comisiones), funding: Number(acu.funding),
      noRealizada,
    } : null;
    let hoy = null;
    if (valuable && foto.decision && foto.decision.capital !== null && foto.ciclo) {
      const total = capital - Number(foto.decision.capital);
      const realizado = Number(foto.ciclo.realizado), comisiones = -Number(foto.ciclo.comisiones);
      const funding = Number(foto.ciclo.funding);
      hoy = { total, base: Number(foto.decision.capital), pct: total / Number(foto.decision.capital),
              realizado, comisiones, funding, abiertas: total - realizado - comisiones - funding };
    }
    return { capital: valuable ? capital : null, posiciones, todasEnVivo, desdeArranque, hoy };
  }

  const api = { deB64url, importarClave, descifrar, mejorFoto, valorar };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else raiz.Nucleo = api;
})(typeof window !== "undefined" ? window : globalThis);
