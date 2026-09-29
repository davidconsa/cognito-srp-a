import { computePasswordClaim, generateSrpA } from "../core/srp.js";
import { DEFAULT_AUTH_ENDPOINT, DEFAULT_CLIENT_ID, DEFAULT_DEVICE, jwtExpiry } from "../core/session.js";
import { cognitoHeaders, mergeState, postJson, readState, requiredEnv } from "./http.js";
import { requestSession } from "./session-lib.js";

// Login SRP completo. Ver README para las variables de entorno.
const resolveSession = async (): Promise<string> => {
  if (process.env.SESSION) return process.env.SESSION;
  if (process.env.RECAPTCHA_TOKEN) return requestSession();
  const stored = readState().session;
  const exp = stored ? jwtExpiry(stored) : undefined;
  if (stored && (!exp || exp.getTime() > Date.now())) return stored;
  throw new Error("Falta SESSION (o API_KEY + USER_DOCUMENT + RECAPTCHA_TOKEN para pedirla)");
};

const endpoint = process.env.AUTH_ENDPOINT ?? DEFAULT_AUTH_ENDPOINT;
const clientId = process.env.CLIENT_ID ?? DEFAULT_CLIENT_ID;
const username = requiredEnv("USERNAME");
const password = requiredEnv("PASSWORD");
const userPoolId = requiredEnv("USER_POOL_ID");

const session = await resolveSession();
const clientMetadata = { session, device: process.env.DEVICE ?? DEFAULT_DEVICE };

const { a, SRP_A } = generateSrpA();
mergeState({ a, SRP_A });
console.error("1) InitiateAuth (USER_SRP_AUTH)...");
const init = (await postJson(endpoint, cognitoHeaders("InitiateAuth"), {
  AuthFlow: "USER_SRP_AUTH",
  AuthParameters: { USERNAME: username, SRP_A },
  ClientMetadata: clientMetadata,
  ClientId: clientId,
})) as { ChallengeName?: string; ChallengeParameters?: Record<string, string>; Session?: string };

if (init.ChallengeName !== "PASSWORD_VERIFIER" || !init.ChallengeParameters) {
  throw new Error("Respuesta inesperada de InitiateAuth: " + JSON.stringify(init));
}

const p = init.ChallengeParameters;
const claim = await computePasswordClaim({
  a,
  srpB: p.SRP_B,
  salt: p.SALT,
  secretBlock: p.SECRET_BLOCK,
  userIdForSrp: p.USER_ID_FOR_SRP,
  userPoolId,
  password,
});
console.error("2) RespondToAuthChallenge (PASSWORD_VERIFIER)...");
const result = await postJson(endpoint, cognitoHeaders("RespondToAuthChallenge"), {
  ChallengeName: "PASSWORD_VERIFIER",
  ClientId: clientId,
  ChallengeResponses: claim,
  ClientMetadata: clientMetadata,
  ...(init.Session ? { Session: init.Session } : {}),
});
console.log(JSON.stringify(result, null, 2));
