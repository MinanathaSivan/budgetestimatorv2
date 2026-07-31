const { findUser, backfillUpn, autoProvisionUser, repairUserName } = require("./tables");

function getClientPrincipal(req) {
  const h = req.headers || {};

  // Path 1: the full base64 x-ms-client-principal (App Service Easy Auth & SWA).
  const header = h["x-ms-client-principal"] || (req.get && req.get("x-ms-client-principal"));
  if (header) {
    try {
      const p = JSON.parse(Buffer.from(header, "base64").toString("utf8"));

      // Easy Auth's decoded shape names claim keys via p.name_typ / p.claims[].typ.
      const rawClaims = p.claims || p.userClaims || [];
      const claims = rawClaims.map((c) => ({
        typ: c.typ || c.type || "",
        val: c.val || c.value || "",
      }));

      const byType = (needle) =>
        claims.find((c) => String(c.typ || "").split("/").pop().toLowerCase() === needle)?.val;

      const userDetails =
        p.userDetails ||
        byType("upn") ||
        byType("preferred_username") ||
        byType("emailaddress") ||
        p.name ||
        h["x-ms-client-principal-name"] ||
        "";

      if (userDetails) {
        return {
          identityProvider: p.identityProvider || p.auth_typ || h["x-ms-client-principal-idp"] || "aad",
          userId: p.userId || byType("objectidentifier") || h["x-ms-client-principal-id"] || "",
          userDetails,
          userRoles: p.userRoles || ["authenticated"],
          claims,
        };
      }
    } catch { /* fall through to header-based path */ }
  }

  // Path 2: individual Easy Auth headers (always set by App Service when the
  // base64 blob is absent or unparsed), plus the SPA-forwarded x-user-* values.
  const name = h["x-ms-client-principal-name"];
  const forwardedEmail = h["x-user-email"];
  const forwardedName = h["x-user-name"] ? decodeURIComponent(h["x-user-name"]) : null;
  const userDetails = name || forwardedEmail || "";
  if (!userDetails) return null;

  const claims = [];
  if (forwardedEmail) {
    claims.push({ typ: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", val: forwardedEmail });
  }
  if (forwardedName) claims.push({ typ: "name", val: forwardedName });

  return {
    identityProvider: h["x-ms-client-principal-idp"] || "aad",
    userId: h["x-ms-client-principal-id"] || "",
    userDetails,
    userRoles: ["authenticated"],
    claims,
  };
}
// Claim keys that can carry a human display name. Matching is done on the LAST
// SEGMENT of the claim type, so both the short OIDC form ("name") and any
// schema-URI form (".../identity/claims/name") are caught without having to
// enumerate every variant a tenant might emit.
const NAME_KEYS   = ["name", "displayname", "commonname", "cn", "nickname", "preferred_username", "unique_name"];
const GIVEN_KEYS  = ["given_name", "givenname", "firstname"];
const FAMILY_KEYS = ["family_name", "familyname", "surname", "lastname"];

const keyOf = (typ) => String(typ || "").split("/").pop().toLowerCase();

/** True when a candidate "name" is really an identifier, not a person's name. */
function looksLikeIdentifier(value, upn, email) {
  if (!value) return true;
  const v = String(value).trim().toLowerCase();
  if (!v) return true;
  if (v === String(upn || "").toLowerCase()) return true;
  if (v === String(email || "").toLowerCase()) return true;
  if (v.includes("@")) return true;                 // UPN / email form
  if (/^[0-9a-f-]{20,}$/i.test(v)) return true;     // GUID / object id
  if (/^[a-z]\d{3,}[a-z]{0,3}$/i.test(v)) return true; // GAD-style id, e.g. z179gt
  return false;
}

function claimByKeys(claims, keys) {
  for (const key of keys) {
    const hit = (claims || []).find((c) => keyOf(c.typ) === key && c.val);
    if (hit) return String(hit.val).trim();
  }
  return null;
}

const titleCase = (s) => s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();

/**
 * Last-resort name derived from the email local part:
 *   sachin.katari@axa.com -> "Sachin Katari"
 * Only used when the token carries no usable name claim. Requires at least two
 * alphabetic segments so identifiers like "z179gt" are never mangled into a
 * fake name.
 */
function deriveNameFromEmail(email) {
  const local = String(email || "").split("@")[0];
  if (!local) return null;
  const parts = local.split(/[._-]+/).filter(Boolean);
  if (parts.length < 2) return null;
  if (!parts.every((p) => /^[a-z]{2,}$/i.test(p))) return null;
  return parts.map(titleCase).join(" ");
}

/** Best available human-readable name, or null when none is usable. */
function resolveDisplayName(claims, upn, email) {
  const direct = claimByKeys(claims, NAME_KEYS);
  if (direct && !looksLikeIdentifier(direct, upn, email)) return direct;

  const given = claimByKeys(claims, GIVEN_KEYS);
  const family = claimByKeys(claims, FAMILY_KEYS);
  const combined = [given, family].filter(Boolean).join(" ").trim();
  if (combined && !looksLikeIdentifier(combined, upn, email)) return combined;

  // No usable name claim in the token — log what we DID get so the missing
  // claim can be identified, then fall back to the email local part.
  console.log(
    "No display-name claim resolved. Claim types present:",
    JSON.stringify((claims || []).map((c) => c.typ)),
  );

  return deriveNameFromEmail(email);
}

function initialsOf(name, fallback) {
  if (name) {
    const parts = name.split(/\s+/).filter(Boolean);
    if (parts.length) {
      return parts.map((w) => w[0]).join("").toUpperCase().slice(0, 2);
    }
  }
  return String(fallback || "").slice(0, 2).toUpperCase();
}

async function authorize(req, requiredRoles) {
  // Step 1: Verify authentication via SWA's header
  const principal = getClientPrincipal(req);
  if (!principal || !principal.userDetails) {
    const e = new Error("No authenticated principal"); e.status = 401; throw e;
  }

  const upn = String(principal.userDetails || "").toLowerCase();
  const oid = principal.userId;

  // Step 2: Resolve email — from x-user-email header (SPA forwards it from
  // /.auth/me) or from claims if present
  const emailFromHeader = req.headers["x-user-email"];
  const email = emailFromHeader ? String(emailFromHeader).toLowerCase().trim() : null;

  let emailFromClaims = null;
  if (principal.claims) {
    const claim = (principal.claims || []).find(
      (c) => c.typ === "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    );
    if (claim) emailFromClaims = String(claim.val).toLowerCase();
  }
  const resolvedEmail = email || emailFromClaims;

  // Display name.
  // IMPORTANT: the `x-ms-client-principal` header that SWA passes to the
  // Functions backend contains only identityProvider / userId / userDetails /
  // userRoles — it does NOT carry the `claims` array. Only /.auth/me exposes
  // claims, and that is client-side. This is why the server-side claim lookup
  // always came back empty and the name fell through to the UPN, then to the
  // email. The SPA therefore forwards the name in `x-user-name`, exactly as it
  // already forwards `x-user-email`. Claims are still checked as a fallback in
  // case a future SWA version starts including them.
  const nameFromHeader = req.headers["x-user-name"]
    ? decodeURIComponent(String(req.headers["x-user-name"])).trim()
    : null;

  const displayName =
    (nameFromHeader && !looksLikeIdentifier(nameFromHeader, upn, resolvedEmail)
      ? nameFromHeader
      : null)
    || resolveDisplayName(principal.claims, upn, resolvedEmail);

  // Step 3: Find the user
  let user = await findUser(resolvedEmail, upn);

  // SECURITY: resolvedEmail can come from the client-supplied `x-user-email`
  // header, so a signed-in user could otherwise send someone else's address and
  // be resolved as that person — including a super_admin. Only accept a matched
  // row if it is not yet bound to a UPN (first sign-in / admin-seeded row) or
  // if its UPN matches the one in the signed principal header.
  if (user && user.upn && upn && String(user.upn).toLowerCase() !== upn) {
    console.error(
      `Identity mismatch: row ${user.email} is bound to ${user.upn} but request presented ${upn}`,
    );
    const e = new Error("Identity mismatch"); e.status = 403; throw e;
  }

  // Step 4: AUTO-PROVISION — any authenticated AXA user who isn't yet in
  // UserRoles gets a 'user' role row created automatically on first sign-in.
  if (!user) {
    try {
      user = await autoProvisionUser({
        email: resolvedEmail,
        upn,
        name: displayName || resolvedEmail || upn,
      });
    } catch (provErr) {
      console.error("Auto-provision failed:", provErr.message);
      const e = new Error("Provisioning failed"); e.status = 500; throw e;
    }
  }

  if (!user) {
    const e = new Error("Could not resolve user"); e.status = 500; throw e;
  }

  // Step 5: Role check (for endpoints that require elevated roles)
  if (requiredRoles && !requiredRoles.includes(user.role)) {
    const e = new Error(`Role ${user.role} not permitted`); e.status = 403; throw e;
  }

  // Step 6: Backfill UPN for existing rows that don't have it yet
  if (resolvedEmail && upn && (!user.upn || user.upn !== upn)) {
    try {
      await backfillUpn(user.email, upn);
    } catch (bfErr) {
      console.error("UPN backfill failed:", bfErr.message);
    }
  }

  // Step 7: Repair stored names. Users auto-provisioned before the claim
  // lookup was fixed have the UPN saved as their name; because the stored
  // value takes precedence, fixing the lookup alone would not correct them.
  // When we now have a proper display name and the stored one is just an
  // identifier, write the good name back once.
  let effectiveName = user.name;
  let effectiveAvatar = user.avatar;
  if (displayName && looksLikeIdentifier(user.name, upn, resolvedEmail)) {
    effectiveName = displayName;
    effectiveAvatar = initialsOf(displayName, resolvedEmail || upn);
    try {
      await repairUserName(user.email, effectiveName, effectiveAvatar);
    } catch (rnErr) {
      console.error("Name repair failed:", rnErr.message);
    }
  }

  const finalName = effectiveName || displayName || resolvedEmail || upn;

  return {
    email: resolvedEmail || upn,
    upn,
    name: finalName,
    oid,
    role: user.role,
    assignedProducts: user.assignedProducts || [],
    avatar: effectiveAvatar || initialsOf(finalName, resolvedEmail || upn),
  };
}

function withAuth(requiredRoles, handler) {
  if (typeof requiredRoles === "function") { handler = requiredRoles; requiredRoles = null; }
  return async function (context, req) {
    try {
      const user = await authorize(req, requiredRoles);
      await handler(context, req, user);
    } catch (err) {
      context.log.error(`[${req.method} ${req.url}] ${err.message}`);
      context.res = {
        status: err.status || 500,
        headers: { "Content-Type": "application/json" },
        body: { error: err.message || "Internal error" },
      };
    }
  };
}

module.exports = { authorize, withAuth };
