import { parseOperation } from "./contract.js";

const element = <T extends HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(id);
  return e as T;
};
const input = element<HTMLTextAreaElement>("input");
const token = element<HTMLInputElement>("token");
let last: Record<string, unknown> = {};
const set = (v: unknown) => {
  input.value = JSON.stringify(v, null, 2);
};
element<HTMLSelectElement>("identity").addEventListener("change", (event) => {
  token.value = (event.target as HTMLSelectElement).value;
});
async function submit(value: unknown): Promise<void> {
  try {
    const op = parseOperation(value);
    const r = await fetch("/api/operate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token.value}` },
      body: JSON.stringify(op),
    });
    const data = (await r.json()) as Record<string, unknown>;
    element("output").textContent = JSON.stringify(data, null, 2);
    element("decision").textContent = r.ok
      ? String(data.state ?? data.status ?? data.integrity ?? "Tenant records")
      : String(data.error ?? "Request rejected");
    element("decision").classList.toggle("bad", !r.ok);
    if (r.ok && !["list", "evidence"].includes(op.operation)) last = data;
  } catch (error) {
    element("decision").textContent = error instanceof Error ? error.message : "Invalid operation";
    element("decision").classList.add("bad");
  }
}
function next(): unknown {
  if (last.kind)
    return {
      operation: "plan",
      data: {
        event_id: last.id,
        playbook: last.kind === "malware-detected" ? "contain-host" : "disable-identity",
      },
    };
  if (last.status === "awaiting_approval")
    return { operation: "approve", record_id: last.id, data: { digest: last.plan_sha256 } };
  if (last.status === "approved")
    return {
      operation: "execute",
      record_id: last.id,
      data: { plan_sha256: last.plan_sha256, idempotency_key: `demo-${last.id}` },
    };
  return { operation: "list" };
}
async function reset(): Promise<void> {
  const r = await fetch("/api/sample", { headers: { Authorization: `Bearer ${token.value}` } });
  const data = (await r.json()) as Record<string, unknown>;
  if (!r.ok) {
    element("decision").textContent = String(data.error ?? "Authentication required");
    return;
  }
  const id = `demo-${Date.now().toString(36)}`;
  data.id = id;
  data.resource = `sim:${id}`;
  set({ operation: "ingest", data });
  last = {};
}
element("submit").addEventListener("click", () => {
  try {
    void submit(JSON.parse(input.value));
  } catch {
    element("decision").textContent = "Invalid JSON";
  }
});
element("next").addEventListener("click", () => set(next()));
element("reset").addEventListener("click", () => void reset());
element("list").addEventListener("click", () => void submit({ operation: "list" }));
element("evidence").addEventListener("click", () => void submit({ operation: "evidence" }));
void reset();
