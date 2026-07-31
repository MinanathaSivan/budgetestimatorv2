// ===========================================================================
// REPLACE the getClientPrincipal() at the top of api/shared/auth.js with this.
//
// App Service Easy Auth and SWA both send the base64 `x-ms-client-principal`
// header, but Easy Auth's payload is the RICHER one — it includes the full
// `claims` array server-side (SWA does not, which is why you had to forward
// x-user-name). This normaliser accepts BOTH shapes so the file keeps working
// on either platform, and it exposes claims as {typ,val} so resolveDisplayName
// and the email lookup you already have keep functioning unchanged.
// ===========================================================================
function getClientPrincipal(req) {
  const header =
    req.headers["x-ms-client-principal"] ||
    (req.get && req.get("x-ms-client-principal"));
  if (!header) return null;

  let p;
  try {
    p = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  } catch {
    return null;
  }

  // Easy Auth uses `userDetails`/`userId`; some SDKs use `name_typ`/`role_typ`
  // keys on claims. Normalise claim entries to { typ, val } either way.
  const claims = (p.claims || []).map((c) => ({
    typ: c.typ || c.type || c[p.name_typ] || "",
    val: c.val || c.value || "",
  }));

  return {
    identityProvider: p.identityProvider || p.auth_typ || "aad",
    userId: p.userId || p.oid || "",
    userDetails: p.userDetails || p.name || "",
    userRoles: p.userRoles || [],
    claims,
  };
}
