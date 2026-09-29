import { writeFileSync } from "node:fs";
import { STATE_FILE } from "./state.js";
import { generateSrpA } from "../core/srp.js";

const result = generateSrpA();
const args = process.argv.slice(2);

if (args.includes("--out")) {
  writeFileSync(STATE_FILE, JSON.stringify({ ...result, createdAt: new Date().toISOString() }, null, 2));
  console.error(`Estado guardado en ${STATE_FILE} (contiene 'a', no lo compartas)`);
}

if (args.includes("--raw")) {
  console.log(result.SRP_A);
} else {
  console.log(JSON.stringify(result, null, 2));
}
