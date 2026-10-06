# @code-402/agent-tools — source of record

This directory is the source of the published npm package `@code-402/agent-tools`.

It was added on 2026-10-06 because the package's `package.json` already declared this repository
(`github.com/89rat/openfang-rail`) while **this repository did not contain the code**. The package
was published with its source under no version control anywhere, which is how a fixed bug stayed
broken in the published artifact: the worker corrected its receipt canonical form on 2026-09-22, and
the SDK — a hand-copied duplicate with no repository — never received the change. Users saw
`verified: false` on every paid call until 2026-10-06.

## One rule

`src/receipt.ts` `canonical()` MUST mirror the sender exactly:
`worker/src/index.ts` `canon` (in the estate's rail repo, `89rat/code402-site`).

```js
if (r.successor || r.stream_state) parts.push(r.successor || "", r.stream_state || "active");
```

Two details are easy to get subtly wrong and both were: the pair is appended only when the flag is
**truthy** (so `stream_state: ""` takes the 11-field form), and `stream_state` falls back to
`"active"` — not `""` — when `successor` is set without it. A cross-check against the rail's own
`POST /v1/receipt/verify` is the fastest way to confirm agreement: it returns the canonical string it
hashed.

## Build

```bash
npm install && npm run build && npm test
```
