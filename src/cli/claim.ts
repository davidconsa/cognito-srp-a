import { existsSync, readFileSync } from "node:fs";
import { STATE_FILE } from "./state.js";
import { computePasswordClaim } from "../core/srp.js";

// Uso:
//   npm run claim -- --challenge respuesta-initiate-auth.json
// Variables: PASSWORD (obligatoria), USER_POOL_ID (obligatoria), CLIENT_ID (opcional),
// SRP_A_PRIVATE (opcional, si no se lee de .srp-state.json).
// Sin --challenge se leen SRP_B, SALT, SECRET_BLOCK y USER_ID_FOR_SRP de env.

const argValue = (name: string): string | undefined => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

const required = (name: string, value: string | undefined): string => {
  if (!value) throw new Error(`Falta ${name}`);
  return value;
};

const challengeFile = argValue("--challenge");
const challenge = challengeFile ? JSON.parse(readFileSync(challengeFile, "utf8")) : {};
const params: Record<string, string> = challenge.ChallengeParameters ?? challenge;

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const a = required("SRP_A_PRIVATE o .srp-state.json (ejecuta 'npm run generate -- --out')", process.env.SRP_A_PRIVATE ?? state.a);

const claim = await computePasswordClaim({
  a,
  srpB: required("SRP_B", params.SRP_B ?? process.env.SRP_B),
  salt: required("SALT", params.SALT ?? process.env.SALT),
  secretBlock: required("SECRET_BLOCK", params.SECRET_BLOCK ?? process.env.SECRET_BLOCK),
  userIdForSrp: required("USER_ID_FOR_SRP", params.USER_ID_FOR_SRP ?? process.env.USER_ID_FOR_SRP),
  userPoolId: required("USER_POOL_ID", process.env.USER_POOL_ID),
  password: required("PASSWORD", process.env.PASSWORD),
});

console.log(
  JSON.stringify(
    {
      ChallengeName: "PASSWORD_VERIFIER",
      ClientId: process.env.CLIENT_ID ?? "28fsp78mbm4sfevo5ciuttf94m",
      ChallengeResponses: claim,
      ...(challenge.Session ? { Session: challenge.Session } : {}),
    },
    null,
    2,
  ),
);
