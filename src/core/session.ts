export const DEFAULT_SESSION_ENDPOINT = "https://mobile.api.dev.io.pe/v1/auth/session";
export const DEFAULT_AUTH_ENDPOINT = "https://mobile.api.dev.io.pe/v1/auth";
export const DEFAULT_CLIENT_ID = "28fsp78mbm4sfevo5ciuttf94m";
export const DEFAULT_DEVICE =
  "eyJwbGF0Zm9ybSI6eyJzbyI6IkFuZHJvaWQiLCJ2ZXJzaW9uIjoiMTYifSwiZGV2aWNlIjp7Im1vZGVsIjoiU00tUzkzOEIiLCJicmFuZCI6InNhbXN1bmcifSwiYXBwVmVyc2lvbiI6IjMuMTAuMCJ9";

export interface SessionRequest {
  authFlow: string;
  userDocument: string;
  version: string;
  recaptchaToken: string;
  platform: string;
}

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/** Busca el token de sesión en la respuesta de /v1/auth/session (el formato exacto puede variar). */
export const extractSession = (response: unknown): string | undefined => {
  if (typeof response === "string") return JWT_RE.test(response.trim()) ? response.trim() : undefined;
  if (!response || typeof response !== "object") return undefined;
  const obj = response as Record<string, unknown>;
  for (const key of ["session", "sessionToken", "token", "accessToken"]) {
    const v = obj[key];
    if (typeof v === "string" && JWT_RE.test(v)) return v;
  }
  for (const v of Object.values(obj)) {
    const found = extractSession(v);
    if (found) return found;
  }
  return undefined;
};

export const jwtExpiry = (jwt: string): Date | undefined => {
  try {
    const b64 = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")));
    return typeof payload.exp === "number" ? new Date(payload.exp * 1000) : undefined;
  } catch {
    return undefined;
  }
};
