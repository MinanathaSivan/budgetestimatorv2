// Authentication helper for the built-in platform auth.
//
// Works with BOTH:
//   - Azure App Service "Easy Auth"  -> /.auth/me returns a bare array
//       [ { id_token, provider_name, user_id, user_claims: [{typ,val}] } ]
//   - Azure Static Web Apps auth     -> /.auth/me returns
//       { clientPrincipal: { userId, userDetails, userRoles, claims:[{typ,val}] } }
//
// Both expose the same /.auth/login/<provider>, /.auth/logout and /.auth/me
// endpoints, so only the /.auth/me PARSING differs. We normalise Easy Auth's
// shape into the clientPrincipal shape the rest of the SPA already expects, so
// App.jsx and api.js need no changes.
//
// References:
//   https://learn.microsoft.com/azure/app-service/configure-authentication-user-identities
//   https://learn.microsoft.com/azure/static-web-apps/user-information

const LOGIN_PROVIDER = "aad"; // Microsoft Entra ID

/** Redirect the browser to the login endpoint. */
export function login(postLoginRedirect = "/") {
  // Easy Auth uses post_login_redirect_uri; SWA accepts it too.
  const target = encodeURIComponent(postLoginRedirect);
  window.location.href = `/.auth/login/${LOGIN_PROVIDER}?post_login_redirect_uri=${target}`;
}

/** Redirect the browser to the logout endpoint. */
export function logout() {
  window.location.href = `/.auth/logout`;
}

/**
 * Fetch the current signed-in principal, normalised to:
 *   { identityProvider, userId, userDetails, userRoles, claims: [{ typ, val }] }
 * Returns null when not signed in.
 */
export async function getClientPrincipal() {
  try {
    const resp = await fetch("/.auth/me", { credentials: "include" });
    if (!resp.ok) return null;
    const payload = await resp.json();

    // --- Static Web Apps shape ---
    if (payload && payload.clientPrincipal) {
      return payload.clientPrincipal;
    }

    // --- App Service Easy Auth shape: a non-empty array of identities ---
    const identity = Array.isArray(payload) ? payload[0] : null;
    if (!identity) return null;

    const claims = (identity.user_claims || []).map((c) => ({
      typ: c.typ || c.type || "",
      val: c.val || c.value || "",
    }));

    // Derive userDetails (UPN/email) the way SWA would populate it.
    const byType = (needle) =>
      claims.find(
        (c) => String(c.typ || "").split("/").pop().toLowerCase() === needle
      );
    const userDetails =
      identity.user_id ||
      byType("upn")?.val ||
      byType("preferred_username")?.val ||
      byType("emailaddress")?.val ||
      "";

    return {
      identityProvider: identity.provider_name || "aad",
      userId:
        byType("objectidentifier")?.val ||
        byType("nameidentifier")?.val ||
        userDetails,
      userDetails,
      userRoles: ["authenticated"],
      claims,
    };
  } catch {
    return null;
  }
}
