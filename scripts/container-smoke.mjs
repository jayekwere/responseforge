import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const image = process.argv[2];
if (!image) throw new Error("Image name required");
const id = execFileSync(
  "docker",
  [
    "run",
    "-d",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--tmpfs",
    "/tmp:rw,nosuid,size=64m",
    "--tmpfs",
    "/app/artifacts:uid=10001,gid=10001,mode=0700",
    "-p",
    "127.0.0.1::8080",
    image,
  ],
  { encoding: "utf8" },
).trim();
try {
  const port = execFileSync("docker", ["port", id, "8080/tcp"], { encoding: "utf8" })
    .trim()
    .split(":")
    .at(-1);
  let response;
  for (let i = 0; i < 40; i++) {
    try {
      response = await fetch(`http://127.0.0.1:${port}/`);
      if (response.ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(response?.ok, "Container did not become ready");
  assert.match(await response.text(), /<title>/);
  assert.match(response.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  assert.equal(
    execFileSync("docker", ["exec", id, "id", "-u"], { encoding: "utf8" }).trim(),
    "10001",
  );
  console.log(
    JSON.stringify({
      container: image,
      uid: 10001,
      http: "passed",
      read_only: true,
      capabilities: "dropped",
    }),
  );
} finally {
  execFileSync("docker", ["rm", "-f", id]);
}
