import { DEFAULT_SESSION_ENDPOINT, extractSession, jwtExpiry, type SessionRequest } from "../core/session.js";
import { mergeState, postJson, requiredEnv } from "./http.js";

// Paso 0: obtiene el token `session` para ClientMetadata.session.
// Variables: API_KEY, USER_DOCUMENT, RECAPTCHA_TOKEN (obligatorias);
// AUTH_FLOW (signup), APP_VERSION (enterprise), PLATFORM (android), SESSION_ENDPOINT.
export const requestSession = async (): Promise<string> => {
  const body: SessionRequest = {
    authFlow: process.env.AUTH_FLOW ?? "signup",
    userDocument: requiredEnv("USER_DOCUMENT"),
    version: process.env.APP_VERSION ?? "enterprise",
    recaptchaToken: requiredEnv("RECAPTCHA_TOKEN"),
    platform: process.env.PLATFORM ?? "android",
  };
  const response = await postJson(
    process.env.SESSION_ENDPOINT ?? DEFAULT_SESSION_ENDPOINT,
    { Accept: "application/json", "Content-Type": "application/json", "x-api-key": requiredEnv("API_KEY") },
    body,
  );
  const session = extractSession(response);
  if (!session) throw new Error("No se encontró el token session en la respuesta: " + JSON.stringify(response));
  mergeState({ session });
  const exp = jwtExpiry(session);
  console.error("Session guardada en el estado" + (exp ? " (expira " + exp.toISOString() + ")" : ""));
  return session;
};
