// ============================================================
//  External client gate  (Netlify Edge Function, Deno)
//  Copy this file to  netlify/edge-functions/gate.js  in the
//  CLIENT's own repo (the one on a *.vyrellabs.com subdomain).
//  ------------------------------------------------------------
//  It guards EVERY path on that subdomain. It reads the signed
//  cookie that vyrellabs.com/api/unlock sets on `.vyrellabs.com`
//  and lets the visitor through only if the cookie is valid for
//  THIS client (CLIENT_SLUG). Otherwise it bounces them to the
//  main site's homepage.
//
//  Required env vars on this site (Netlify → Environment variables):
//    ACCESS_SECRET   same value as the main vyrellabs.com site
//    CLIENT_SLUG     this client's slug, must match the `slug` in
//                    the main site's CODES entry (e.g. "acme")
//    VYREL_HOME      optional, defaults to https://vyrellabs.com
// ============================================================

export default async (request, context) => {
  const slug = Netlify.env.get("CLIENT_SLUG") || "goldensandhounds";
  const secret = Netlify.env.get("ACCESS_SECRET") || "CHANGE_ME_dev_secret";
  const home = Netlify.env.get("VYREL_HOME") || "https://vyrellabs.com";

  const token = getCookie(request, "vyrel_access");
  if (token && (await verify(secret, token, slug))) {
    return context.next(); // valid cookie for this client -> serve the site
  }

  return Response.redirect(`${home}/?locked=${encodeURIComponent(slug)}`, 302);
};

// Guard the whole site.
export const config = { path: "/*" };

// ---- helpers (identical crypto to the main site's gate) ----
function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

async function verify(secret, token, slug) {
  const dot = token.lastIndexOf(".");
  if (dot < 0) return false;

  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const expBuf = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const expected = b64url(new Uint8Array(expBuf));
  if (expected !== sig) return false;

  let data;
  try { data = JSON.parse(fromB64url(payload)); } catch (_) { return false; }

  if (!data || data.slug !== slug) return false;               // cookie is for a different client
  if (typeof data.exp !== "number" || Date.now() > data.exp) return false; // expired
  return true;
}

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
