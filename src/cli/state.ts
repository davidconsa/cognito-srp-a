import { resolve } from "node:path";

export const STATE_FILE = resolve(process.env.SRP_STATE_FILE ?? ".srp-state.json");
