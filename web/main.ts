import { computePasswordClaim, generateSrpA, srpAFromPrivate } from "../src/core/srp.js";

const DEFAULT_DEVICE =
  "eyJwbGF0Zm9ybSI6eyJzbyI6IkFuZHJvaWQiLCJ2ZXJzaW9uIjoiMTYifSwiZGV2aWNlIjp7Im1vZGVsIjoiU00tUzkzOEIiLCJicmFuZCI6InNhbXN1bmcifSwiYXBwVmVyc2lvbiI6IjMuMTAuMCJ9";

const el = <T extends HTMLElement = HTMLInputElement>(id: string): T => {
  const node = document.getElementById(id);
  if (!node) throw new Error("Elemento no encontrado: " + id);
  return node as T;
};
const val = (id: string): string => el<HTMLInputElement>(id).value.trim();

const shellQuote = (s: string): string => "'" + s.replace(/'/g, "'\\''") + "'";

const toCurl = (target: string, body: unknown): string =>
  [
    "curl --location " + shellQuote(val("endpoint")),
    "--header 'content-type: application/x-amz-json-1.1'",
    "--header " + shellQuote("x-amz-target: AWSCognitoIdentityProviderService." + target),
    "--header 'cache-control: no-store'",
    "--header 'x-amz-user-agent: aws-amplify/6.10.2 auth/4 framework/201'",
    "--data " + shellQuote(JSON.stringify(body, null, 2)),
  ].join(" \\\n");

const clientMetadata = (): Record<string, string> => {
  const meta: Record<string, string> = {};
  if (val("session")) meta.session = val("session");
  if (val("device")) meta.device = val("device");
  return meta;
};

const renderInitiate = (): void => {
  const srpA = el<HTMLTextAreaElement>("srpA").value;
  if (!srpA) return;
  const body = {
    AuthFlow: "USER_SRP_AUTH",
    AuthParameters: { USERNAME: val("username"), SRP_A: srpA },
    ClientMetadata: clientMetadata(),
    ClientId: val("clientId"),
  };
  el<HTMLTextAreaElement>("initBody").value = JSON.stringify(body, null, 2);
  el<HTMLTextAreaElement>("initCurl").value = toCurl("InitiateAuth", body);
};

const generate = (): void => {
  const { a, SRP_A } = generateSrpA();
  el<HTMLTextAreaElement>("srpA").value = SRP_A;
  el<HTMLTextAreaElement>("aPriv").value = a;
  sessionStorage.setItem("srp-a", a);
  renderInitiate();
};

const claim = async (): Promise<void> => {
  const errorEl = el<HTMLParagraphElement>("claimError");
  errorEl.textContent = "";
  try {
    const a = el<HTMLTextAreaElement>("aPriv").value.trim();
    if (!a) throw new Error("Primero genera SRP_A (paso 1) o pega el valor de a.");
    const parsed = JSON.parse(val("challengeJson") || "{}");
    const params = parsed.ChallengeParameters ?? parsed;
    for (const k of ["SRP_B", "SALT", "SECRET_BLOCK", "USER_ID_FOR_SRP"]) {
      if (!params[k]) throw new Error("Falta ChallengeParameters." + k);
    }
    if (!val("userPoolId")) throw new Error("Falta USER_POOL_ID");
    if (!el<HTMLInputElement>("password").value) throw new Error("Falta Password");
    const result = await computePasswordClaim({
      a,
      srpB: params.SRP_B,
      salt: params.SALT,
      secretBlock: params.SECRET_BLOCK,
      userIdForSrp: params.USER_ID_FOR_SRP,
      userPoolId: val("userPoolId"),
      password: el<HTMLInputElement>("password").value,
    });
    const body: Record<string, unknown> = {
      ChallengeName: "PASSWORD_VERIFIER",
      ClientId: val("clientId"),
      ChallengeResponses: result,
      ClientMetadata: clientMetadata(),
    };
    if (parsed.Session) body.Session = parsed.Session;
    el("signature").value = result.PASSWORD_CLAIM_SIGNATURE;
    el("timestamp").value = result.TIMESTAMP;
    el<HTMLTextAreaElement>("claimBody").value = JSON.stringify(body, null, 2);
    el<HTMLTextAreaElement>("claimCurl").value = toCurl("RespondToAuthChallenge", body);
  } catch (err) {
    errorEl.textContent = err instanceof Error ? err.message : String(err);
  }
};

el("device").value = DEFAULT_DEVICE;
const storedA = sessionStorage.getItem("srp-a");
if (storedA) {
  el<HTMLTextAreaElement>("aPriv").value = storedA;
  el<HTMLTextAreaElement>("srpA").value = srpAFromPrivate(storedA);
  renderInitiate();
}

el<HTMLButtonElement>("btnGenerate").addEventListener("click", generate);
el<HTMLButtonElement>("btnClaim").addEventListener("click", () => void claim());
for (const id of ["endpoint", "clientId", "username", "device", "session"]) {
  el(id).addEventListener("input", renderInitiate);
}
el<HTMLTextAreaElement>("aPriv").addEventListener("change", () => {
  const a = el<HTMLTextAreaElement>("aPriv").value.trim();
  if (!/^[0-9a-f]+$/i.test(a)) return;
  el<HTMLTextAreaElement>("srpA").value = srpAFromPrivate(a);
  sessionStorage.setItem("srp-a", a);
  renderInitiate();
});
document.querySelectorAll<HTMLButtonElement>("button.copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const target = document.getElementById(btn.dataset.target ?? "") as HTMLInputElement | null;
    if (!target?.value) return;
    await navigator.clipboard.writeText(target.value);
    const label = btn.textContent;
    btn.textContent = "¡Copiado!";
    setTimeout(() => (btn.textContent = label), 1200);
  });
});
