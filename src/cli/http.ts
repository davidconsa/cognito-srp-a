import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { STATE_FILE } from "./state.js";

export const readState = (): Record<string, string> =>
  existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};

export const mergeState = (patch: Record<string, string>): void => {
  writeFileSync(STATE_FILE, JSON.stringify({ ...readState(), ...patch }, null, 2));
};

export const requiredEnv = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (!v) throw new Error("Falta la variable de entorno " + name);
  return v;
};

export const postJson = async (url: string, headers: Record<string, string>, body: unknown): Promise<unknown> => {
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  let data: unknown = text;
  try {
    data = JSON.parse(text);
  } catch {
    // respuesta no JSON
  }
  if (!res.ok) throw new Error("HTTP " + res.status + " " + url + ": " + text.slice(0, 500));
  return data;
};

export const cognitoHeaders = (target: string): Record<string, string> => ({
  "content-type": "application/x-amz-json-1.1",
  "x-amz-target": "AWSCognitoIdentityProviderService." + target,
  "cache-control": "no-store",
  "x-amz-user-agent": "aws-amplify/6.10.2 auth/4 framework/201",
});
