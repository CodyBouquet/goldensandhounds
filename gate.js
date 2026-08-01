// ============================================================
//  Edge gate for /clients/*   (Netlify Edge Function, Deno)
//  ------------------------------------------------------------
//  Runs BEFORE any file under /clients/ is served — including
//  HTML, CSS, and images. It verifies the signed cookie issued
//  by /api/unlock. No valid cookie for THIS client -> the visitor
//  is bounced back to the homepage. This is what makes the client
//  sites genuinely un-viewable without a valid access code.
// ============================================================

export default async (request, context) => {
  const url = new URL(request.url);

  // /clients/<slug>/...  ->  slug is the folder being requested
  const parts = url.pathname.split("/").filter(Boolean); // ["clients", "<slug>", ...]
  const slug = parts[1] || "";

  const secret = Netlify.env.get("ACCESS_SECRET") || "CHANGE_ME_dev_secret";
  const token = getCookie(request, "vyrel_access");

  if (token && (await verify(secret, token, slug))) {
    return context.next(); // cookie is valid for this client -> serve the files
  }

  // Locked: send them home with a hint so the page can explain.
  return Response.redirect(`${url.origin}/?locked=${encodeURIComponent(slug)}`, 302);
};

export const config = { path: "/clients/*" };

// ---- helpers ----
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
