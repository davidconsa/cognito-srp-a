import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { bigIntFromHex, hexToBytes, modPow, padHex } from "../core/hex.js";
import {
  N,
  cognitoTimestamp,
  computeClientS,
  computePasswordClaim,
  computeX,
  g,
  generateSrpA,
  getK,
  srpAFromPrivate,
} from "../core/srp.js";

// Simula el lado servidor de Cognito y verifica que cliente y servidor derivan el mismo S
// y la misma firma PASSWORD_CLAIM_SIGNATURE.

let failures = 0;
const check = (name: string, ok: boolean) => {
  console.log(`${ok ? "OK  " : "FAIL"} ${name}`);
  if (!ok) failures++;
};

const { a, SRP_A } = generateSrpA();
check("SRP_A es hex", /^[0-9a-f]+$/.test(SRP_A));
check("SRP_A <= 768 chars", SRP_A.length <= 768 && SRP_A.length > 700);
check("SRP_A = g^a mod N", srpAFromPrivate(a) === SRP_A);
check("timestamp formato Cognito", cognitoTimestamp(new Date(Date.UTC(2026, 8, 3, 7, 5, 9))) === "Thu Sep 3 07:05:09 UTC 2026");

// Lado servidor simulado
const poolName = "TestPool";
const userId = "baa2df1a-95c5-4b25-812e-5dcea6ee917a";
const password = "Secreto123!";
const saltHex = randomBytes(16).toString("hex");
const x = await computeX(saltHex, poolName, userId, password);
const v = modPow(g, x, N);
const k = await getK();
const b = bigIntFromHex(randomBytes(128).toString("hex")) % N;
const B = (k * v + modPow(g, b, N)) % N;
const A = bigIntFromHex(SRP_A);
const aBig = bigIntFromHex(a);

const { S: clientS, u } = await computeClientS({ a: aBig, A, B, saltHex, poolName, userId, password });
const serverS = modPow((A * modPow(v, u, N)) % N, b, N);
check("S cliente == S servidor", clientS === serverS);

// Firma esperada calculada con node:crypto (implementación independiente de Web Crypto)
const secretBlock = randomBytes(64).toString("base64");
const date = new Date();
const claim = await computePasswordClaim({
  a,
  srpB: B.toString(16),
  salt: saltHex,
  secretBlock,
  userIdForSrp: userId,
  userPoolId: "us-east-1_" + poolName,
  password,
  date,
});
const key = Buffer.from(
  hkdfSync("sha256", hexToBytes(padHex(serverS)), hexToBytes(padHex(u)), "Caldera Derived Key", 16),
);
const expected = createHmac("sha256", key)
  .update(poolName)
  .update(userId)
  .update(Buffer.from(secretBlock, "base64"))
  .update(cognitoTimestamp(date))
  .digest("base64");
check("PASSWORD_CLAIM_SIGNATURE coincide con servidor", claim.PASSWORD_CLAIM_SIGNATURE === expected);
check("k = H(N||g)", k === bigIntFromHex(createHash("sha256").update(hexToBytes(padHex(N) + padHex(g))).digest("hex")));

if (failures) {
  console.error(failures + " verificaciones fallaron");
  process.exit(1);
}
console.log("Selftest OK");
