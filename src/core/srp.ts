import {
  base64ToBytes,
  bigIntFromHex,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  hexToBytes,
  modPow,
  padHex,
  utf8,
} from "./hex.js";

// Primo de 3072 bits (RFC 3526, grupo 15) usado por Cognito.
export const N_HEX =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
  "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
  "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
  "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
  "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

export const N = bigIntFromHex(N_HEX);
export const g = 2n;

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("Web Crypto no disponible (requiere Node 18+ o navegador moderno)");
  return c.subtle;
};

const sha256 = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await subtle().digest("SHA-256", data as BufferSource));

const sha256Hex = async (data: Uint8Array): Promise<string> => bytesToHex(await sha256(data));

const hmacSha256 = async (key: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
  const k = await subtle().importKey("raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, data as BufferSource));
};

let kCache: bigint | undefined;
export const getK = async (): Promise<bigint> => {
  kCache ??= bigIntFromHex(await sha256Hex(hexToBytes(padHex(N) + padHex(g))));
  return kCache;
};

export interface SrpAResult {
  /** Exponente privado (hex). Secreto: solo sirve para este intento de login. */
  a: string;
  /** Valor público para AuthParameters.SRP_A (hex). */
  SRP_A: string;
}

export const generateSrpA = (): SrpAResult => {
  for (;;) {
    const bytes = new Uint8Array(128);
    globalThis.crypto.getRandomValues(bytes);
    const a = bigIntFromHex(bytesToHex(bytes)) % N;
    if (a === 0n) continue;
    const A = modPow(g, a, N);
    if (A % N === 0n) continue;
    return { a: a.toString(16), SRP_A: A.toString(16) };
  }
};

export const srpAFromPrivate = (aHex: string): string => modPow(g, bigIntFromHex(aHex), N).toString(16);

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** Formato de Cognito: "Tue Sep 29 17:42:01 UTC 2026" (día sin cero a la izquierda). */
export const cognitoTimestamp = (date: Date = new Date()): string => {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${WEEKDAYS[date.getUTCDay()]} ${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC ${date.getUTCFullYear()}`
  );
};

export interface PasswordClaimInput {
  /** Exponente privado devuelto por generateSrpA. */
  a: string;
  /** ChallengeParameters.SRP_B */
  srpB: string;
  /** ChallengeParameters.SALT */
  salt: string;
  /** ChallengeParameters.SECRET_BLOCK */
  secretBlock: string;
  /** ChallengeParameters.USER_ID_FOR_SRP */
  userIdForSrp: string;
  /** Ej: us-east-1_AbCdEf123 (o solo la parte después de "_") */
  userPoolId: string;
  password: string;
  date?: Date;
}

export interface PasswordClaimResult {
  PASSWORD_CLAIM_SIGNATURE: string;
  PASSWORD_CLAIM_SECRET_BLOCK: string;
  TIMESTAMP: string;
  USERNAME: string;
}

export const poolNameFrom = (userPoolId: string): string =>
  userPoolId.includes("_") ? userPoolId.split("_")[1] : userPoolId;

/** Calcula S (secreto compartido) del lado cliente. Exportado para el selftest. */
export const computeClientS = async (p: {
  a: bigint;
  A: bigint;
  B: bigint;
  saltHex: string;
  poolName: string;
  userId: string;
  password: string;
}): Promise<{ S: bigint; u: bigint }> => {
  if (p.B % N === 0n) throw new Error("SRP_B inválido (B mod N == 0)");
  const u = bigIntFromHex(await sha256Hex(hexToBytes(padHex(p.A) + padHex(p.B))));
  if (u === 0n) throw new Error("u == 0");
  const x = await computeX(p.saltHex, p.poolName, p.userId, p.password);
  const k = await getK();
  const base = (((p.B - k * modPow(g, x, N)) % N) + N) % N;
  const S = modPow(base, p.a + u * x, N);
  return { S, u };
};

export const computeX = async (saltHex: string, poolName: string, userId: string, password: string): Promise<bigint> => {
  const inner = await sha256Hex(utf8(`${poolName}${userId}:${password}`));
  return bigIntFromHex(await sha256Hex(hexToBytes(padHex(bigIntFromHex(saltHex)) + inner)));
};

const hkdf16 = async (ikm: Uint8Array, salt: Uint8Array): Promise<Uint8Array> => {
  const prk = await hmacSha256(salt, ikm);
  const okm = await hmacSha256(prk, concatBytes(utf8("Caldera Derived Key"), new Uint8Array([1])));
  return okm.slice(0, 16);
};

export const computePasswordClaim = async (input: PasswordClaimInput): Promise<PasswordClaimResult> => {
  const a = bigIntFromHex(input.a.trim());
  const A = modPow(g, a, N);
  const B = bigIntFromHex(input.srpB.trim());
  const poolName = poolNameFrom(input.userPoolId.trim());
  const userId = input.userIdForSrp.trim();
  const { S, u } = await computeClientS({
    a,
    A,
    B,
    saltHex: input.salt.trim(),
    poolName,
    userId,
    password: input.password,
  });
  const key = await hkdf16(hexToBytes(padHex(S)), hexToBytes(padHex(u)));
  const TIMESTAMP = cognitoTimestamp(input.date);
  const secretBlock = input.secretBlock.trim();
  const message = concatBytes(utf8(poolName), utf8(userId), base64ToBytes(secretBlock), utf8(TIMESTAMP));
  return {
    PASSWORD_CLAIM_SIGNATURE: bytesToBase64(await hmacSha256(key, message)),
    PASSWORD_CLAIM_SECRET_BLOCK: secretBlock,
    TIMESTAMP,
    USERNAME: userId,
  };
};
