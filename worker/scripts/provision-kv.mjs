// Creates the NONCES KV namespace and writes its id into wrangler.jsonc
// automatically — so you never hand-edit the config. Run after `wrangler login`.
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
const cfgPath = new URL("../wrangler.jsonc", import.meta.url);
let out = "";
try { out = execSync("npx wrangler kv namespace create NONCES", { encoding: "utf8", stdio: ["ignore","pipe","inherit"] }); }
catch (e) { console.error("KV create failed — are you logged in? run: npx wrangler login"); process.exit(1); }
const m = out.match(/id"?\s*[:=]\s*"([0-9a-fA-F]{32})"/);
if (!m) { console.error("Could not find the namespace id in wrangler output:\n" + out); process.exit(1); }
const id = m[1];
let cfg = readFileSync(cfgPath, "utf8");
if (cfg.includes("<REPLACE_WITH_KV_ID>")) cfg = cfg.replace("<REPLACE_WITH_KV_ID>", id);
else cfg = cfg.replace(/("binding":\s*"NONCES",\s*"id":\s*")[^"]*(")/, `$1${id}$2`);
writeFileSync(cfgPath, cfg);
console.log(`NONCES id ${id} written into wrangler.jsonc ✓`);
