/* ==========================================================
   Open Shelf — Amazon Cognito managed login
   Authorization code flow with PKCE (S256), public client.

   • No client secret exists in this file (public app client).
   • Passwords are entered only on Cognito's managed login pages,
     never on this site.
   • Tokens are kept in sessionStorage (this browser tab only) and
     cleared on logout or expiry. The refresh token is not kept.
   • Signed-in status here is for the UI only. Your backend API must
     verify the access token itself (implemented separately).
   ========================================================== */
(function () {
  "use strict";

  const CONFIG = {
    domain: "https://us-east-1iyrfgs5g4.auth.us-east-1.amazoncognito.com",
    clientId: "7ujoakbhmp92j5t5fgdpdtj1e8",
    // Must exactly match "Allowed callback URLs" on the app client.
    redirectUri: "https://d3d75snbrdu0ih.cloudfront.net/login.html",
    // Must exactly match "Allowed sign-out URLs" on the app client.
    logoutUri: "https://d3d75snbrdu0ih.cloudfront.net/index.html",
    // Must be enabled under the app client's OpenID Connect scopes.
    scope: "openid email",
    issuerPrefix: "https://cognito-idp.us-east-1.amazonaws.com/",
    afterLoginPage: "index.html"
  };

  const TX_KEY = "openshelf.auth.tx";            // state + PKCE verifier (single use)
  const SESSION_KEY = "openshelf.auth.session";  // tokens for this tab
  const TX_MAX_AGE_MS = 10 * 60 * 1000;          // sign-in attempt must finish within 10 min
  const CLOCK_SKEW_MS = 30 * 1000;

  const MESSAGES = {
    state: "That sign-in attempt couldn't be verified, so it was stopped. Please try again.",
    cancelled: "Sign-in was cancelled.",
    provider: "The sign-in service reported a problem. Please try again.",
    exchange: "We couldn't finish signing you in. Please try again.",
    token: "We couldn't finish signing you in. Please try again.",
    crypto: "Secure sign-in needs HTTPS and an up-to-date browser.",
    unknown: "Something went wrong. Please try again."
  };

  class AuthError extends Error {
    constructor(code) {
      super(code);
      this.code = code;
    }
  }

  /* ---------- Encoding and crypto helpers ---------- */

  function base64UrlEncode(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlDecodeToString(input) {
    let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "===".slice((b64.length + 3) % 4);
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }

  function cryptoAvailable() {
    return Boolean(window.isSecureContext && window.crypto &&
                   window.crypto.getRandomValues && window.crypto.subtle);
  }

  // Cryptographically random, URL-safe string.
  function randomString(byteLength) {
    const bytes = new Uint8Array(byteLength);
    window.crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  // PKCE S256: BASE64URL(SHA-256(ASCII(code_verifier)))
  async function pkceChallenge(verifier) {
    const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return base64UrlEncode(new Uint8Array(digest));
  }

  // Comparison that doesn't stop at the first differing character.
  function safeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function decodeJwtPayload(jwt) {
    const parts = String(jwt || "").split(".");
    if (parts.length !== 3) throw new AuthError("token");
    return JSON.parse(base64UrlDecodeToString(parts[1]));
  }

  /* ---------- Storage helpers ---------- */

  function readJson(key) {
    try {
      const raw = sessionStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(TX_KEY);
  }

  /* ---------- Start login / registration ---------- */

  async function startAuthorization(path) {
    if (!cryptoAvailable()) throw new AuthError("crypto");

    const state = randomString(32);     // 256 bits
    const verifier = randomString(64);  // 86 characters (RFC 7636 allows 43–128)
    const challenge = await pkceChallenge(verifier);

    sessionStorage.setItem(TX_KEY, JSON.stringify({ state, verifier, createdAt: Date.now() }));

    const query = [
      ["response_type", "code"],
      ["client_id", CONFIG.clientId],
      ["redirect_uri", CONFIG.redirectUri],
      ["scope", CONFIG.scope],
      ["state", state],
      ["code_challenge", challenge],
      ["code_challenge_method", "S256"]
    ].map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");

    window.location.assign(CONFIG.domain + path + "?" + query);
  }

  function login() { return startAuthorization("/oauth2/authorize"); }
  function register() { return startAuthorization("/signup"); }

  /* ---------- Callback processing (runs on login.html) ---------- */

  function isCallback() {
    const params = new URLSearchParams(window.location.search);
    return params.has("code") || params.has("error");
  }

  function validateIdToken(idToken) {
    const claims = decodeJwtPayload(idToken);
    const now = Date.now();
    if (claims.aud !== CONFIG.clientId) throw new AuthError("token");
    if (claims.token_use !== "id") throw new AuthError("token");
    if (typeof claims.iss !== "string" || !claims.iss.startsWith(CONFIG.issuerPrefix)) throw new AuthError("token");
    if (typeof claims.exp !== "number" || claims.exp * 1000 <= now - CLOCK_SKEW_MS) throw new AuthError("token");
    return claims;
  }

  async function handleCallback() {
    const url = new URL(window.location.href);
    const code = url.searchParams.get("code");
    const returnedState = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    // Remove code, state and any error from the address bar and history right away.
    window.history.replaceState(null, "", url.pathname + url.hash);

    // The stored state and verifier are single use: remove them before anything else.
    const tx = readJson(TX_KEY);
    sessionStorage.removeItem(TX_KEY);

    if (!tx || !returnedState || !safeEqual(tx.state, returnedState) ||
        typeof tx.createdAt !== "number" || Date.now() - tx.createdAt > TX_MAX_AGE_MS) {
      throw new AuthError("state");
    }
    if (error) throw new AuthError(error === "access_denied" ? "cancelled" : "provider");
    if (!code) throw new AuthError("provider");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CONFIG.clientId,
      code: code,
      redirect_uri: CONFIG.redirectUri,
      code_verifier: tx.verifier
    });

    let response;
    try {
      response = await fetch(CONFIG.domain + "/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer"
      });
    } catch (e) {
      throw new AuthError("exchange");
    }
    if (!response.ok) throw new AuthError("exchange");

    const tokens = await response.json();
    if (!tokens.access_token || !tokens.id_token || String(tokens.token_type).toLowerCase() !== "bearer") {
      throw new AuthError("token");
    }
    const claims = validateIdToken(tokens.id_token);

    const expiresIn = Number(tokens.expires_in) > 0 ? Number(tokens.expires_in) : 3600;
    const expiresAt = Math.min(Date.now() + expiresIn * 1000, claims.exp * 1000);

    // The refresh token is deliberately not stored.
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      expiresAt: expiresAt
    }));
    return claims;
  }

  /* ---------- Session ---------- */

  function getSession() {
    const stored = readJson(SESSION_KEY);
    if (!stored || typeof stored.expiresAt !== "number" || stored.expiresAt - CLOCK_SKEW_MS <= Date.now()) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
    try {
      const claims = decodeJwtPayload(stored.idToken);
      return {
        email: claims.email || claims["cognito:username"] || "your account",
        name: claims.name || "",
        accessToken: stored.accessToken,
        idToken: stored.idToken,
        expiresAt: stored.expiresAt
      };
    } catch (e) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
  }

  function getAccessToken() {
    const session = getSession();
    return session ? session.accessToken : null;
  }

  function logout() {
    clearSession();
    const query = "client_id=" + encodeURIComponent(CONFIG.clientId) +
                  "&logout_uri=" + encodeURIComponent(CONFIG.logoutUri);
    // Ends the managed login session too, so the next login asks for credentials again.
    window.location.assign(CONFIG.domain + "/logout?" + query);
  }

  /* ---------- Page wiring ---------- */

  function showState(stateName) {
    document.querySelectorAll("[data-auth-when]").forEach((el) => {
      el.hidden = el.getAttribute("data-auth-when") !== stateName;
    });
  }

  function render() {
    const session = getSession();
    showState(session ? "signed-in" : "signed-out");
    document.querySelectorAll('[data-auth-field="email"]').forEach((el) => {
      el.textContent = session ? session.email : "";   // textContent: never parsed as HTML
    });
  }

  function showMessage(code) {
    const text = MESSAGES[code] || MESSAGES.unknown;
    document.querySelectorAll("[data-auth-message]").forEach((el) => {
      el.textContent = text;
      el.hidden = false;
    });
  }

  const ACTIONS = { login: login, register: register, logout: logout };

  function wireActions() {
    document.querySelectorAll("[data-auth-action]").forEach((el) => {
      el.addEventListener("click", async (event) => {
        const action = ACTIONS[el.getAttribute("data-auth-action")];
        if (!action) return;
        event.preventDefault();
        el.setAttribute("aria-disabled", "true");
        try {
          await action();
        } catch (e) {
          el.removeAttribute("aria-disabled");
          showMessage(e instanceof AuthError ? e.code : "unknown");
        }
      });
    });
  }

  async function init() {
    wireActions();

    if (document.body.getAttribute("data-page") === "login" && isCallback()) {
      showState("processing");
      try {
        await handleCallback();
        window.location.replace(CONFIG.afterLoginPage);
        return;
      } catch (e) {
        clearSession();
        render();
        showMessage(e instanceof AuthError ? e.code : "unknown");
        return;
      }
    }
    render();
  }

  // Re-check status when a page is restored from the back/forward cache.
  window.addEventListener("pageshow", (event) => { if (event.persisted) render(); });

  // Small API for later milestones (e.g. attaching the access token to backend calls).
  window.OpenShelfAuth = Object.freeze({ login, register, logout, getSession, getAccessToken });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();