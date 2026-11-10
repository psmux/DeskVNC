#!/usr/bin/env node
// Upload an Android App Bundle to a Google Play track through the Play
// Developer API (androidpublisher v3). No dependencies: it signs the service
// account's token request itself with node:crypto.
//
//   PLAY_SERVICE_ACCOUNT_JSON='{...}' node mobile/scripts/play-upload.mjs \
//     --package com.psmux.deskvnc.mobile --aab app.aab [--track internal] \
//     [--status completed|draft] [--notes "What changed"] [--notes-file f]
//
// The service account must be invited in Play Console (Users and permissions)
// with permission to release to testing tracks for this app. The app record
// must already exist in Play Console; the API cannot create one.
//
// A new app that has never been reviewed only takes draft releases, so when
// Play answers "Only releases with status draft may be created on draft app"
// the release is retried as a draft, which then has to be rolled out by hand
// in Play Console.

import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";

function args() {
  const out = { track: "internal", status: "completed", notes: "", lang: "en-US" };
  const a = process.argv.slice(2);
  for (let i = 0; i < a.length; i += 2) {
    const k = a[i].replace(/^--/, "");
    if (!(k in out) && !["package", "aab", "notes-file"].includes(k)) {
      throw new Error(`Unknown option ${a[i]}`);
    }
    out[k] = a[i + 1];
  }
  if (out["notes-file"]) out.notes = readFileSync(out["notes-file"], "utf8").trim();
  if (!out.package || !out.aab) throw new Error("--package and --aab are required");
  return out;
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");

async function token(sa) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(
    JSON.stringify({
      iss: sa.client_email,
      scope: "https://www.googleapis.com/auth/androidpublisher",
      aud: sa.token_uri || "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
    }),
  );
  const signer = createSign("RSA-SHA256");
  signer.update(`${head}.${claims}`);
  const jwt = `${head}.${claims}.${b64url(signer.sign(sa.private_key))}`;
  const res = await fetch(sa.token_uri || "https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`Token request failed: ${res.status} ${body.error || ""} ${body.error_description || ""}`);
  return body.access_token;
}

async function main() {
  const o = args();
  const raw = process.env.PLAY_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("PLAY_SERVICE_ACCOUNT_JSON is not set");
  const sa = JSON.parse(raw);
  const auth = { authorization: `Bearer ${await token(sa)}` };
  const api = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${o.package}`;
  const upload = `https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/${o.package}`;

  const call = async (url, init = {}) => {
    const res = await fetch(url, { ...init, headers: { ...auth, ...(init.headers || {}) } });
    const text = await res.text();
    const json = text ? JSON.parse(text) : {};
    if (!res.ok) {
      const err = new Error(`${init.method || "GET"} ${url.replace(/\?.*/, "")}: ${res.status} ${json.error?.message || text}`);
      err.playMessage = json.error?.message || "";
      throw err;
    }
    return json;
  };

  const edit = await call(`${api}/edits`, { method: "POST" });
  console.log(`Opened edit ${edit.id}`);

  const bundle = await call(`${upload}/edits/${edit.id}/bundles?uploadType=media`, {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body: readFileSync(o.aab),
  });
  console.log(`Uploaded bundle, versionCode ${bundle.versionCode}`);

  const release = (status) => ({
    track: o.track,
    releases: [
      {
        versionCodes: [String(bundle.versionCode)],
        status,
        ...(o.notes ? { releaseNotes: [{ language: o.lang, text: o.notes.slice(0, 500) }] } : {}),
      },
    ],
  });

  let status = o.status;
  try {
    await call(`${api}/edits/${edit.id}/tracks/${o.track}`, { method: "PUT", body: JSON.stringify(release(status)), headers: { "content-type": "application/json" } });
  } catch (e) {
    if (status !== "draft" && /draft app/i.test(e.playMessage)) {
      console.log("Play only takes draft releases until the app has been reviewed once, so this one is a draft.");
      status = "draft";
      await call(`${api}/edits/${edit.id}/tracks/${o.track}`, { method: "PUT", body: JSON.stringify(release(status)), headers: { "content-type": "application/json" } });
    } else {
      throw e;
    }
  }

  await call(`${api}/edits/${edit.id}:commit`, { method: "POST" });
  console.log(`Committed: versionCode ${bundle.versionCode} on the ${o.track} track as ${status}.`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
