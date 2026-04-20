// Done is better than perfect 

const inputEl = document.getElementById("input") as HTMLTextAreaElement;
const outputEl = document.getElementById("output") as HTMLPreElement;
const runBtn = document.getElementById("run") as HTMLButtonElement;
const sampleBtn = document.getElementById("sample") as HTMLButtonElement;
const statusEl = document.getElementById("status") as HTMLSpanElement;

const PLACEHOLDER_RE = /<<[A-Z_]+_[0-9a-f]{8}>>/g;

const SAMPLE_HAR = JSON.stringify(
  {
    log: {
      version: "1.2",
      creator: { name: "pentect-sample", version: "0.1" },
      entries: [
        {
          startedDateTime: "2026-04-19T10:00:00.000Z",
          time: 42,
          request: {
            method: "GET",
            url: "http://jira.corp.internal/api/issues/1001",
            httpVersion: "HTTP/1.1",
            cookies: [{ name: "session", value: "s_GXyZabc123" }],
            headers: [
              { name: "Host", value: "jira.corp.internal" },
              {
                name: "Authorization",
                value:
                  "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIn0.s7sig",
              },
            ],
            queryString: [],
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: 200,
            statusText: "OK",
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: [{ name: "Content-Type", value: "application/json" }],
            content: {
              size: 80,
              mimeType: "application/json",
              text: '{"id": 1001, "reporter": "alice@corp.example", "ip": "10.0.5.42"}',
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: 80,
          },
          cache: {},
          timings: { send: 1, wait: 40, receive: 1 },
        },
      ],
    },
  },
  null,
  2
);

type MaskResponse = {
  masked_text: string;
  map: Record<string, unknown>;
  summary: { total_masked?: number } & Record<string, unknown>;
};

function clearNode(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function renderMasked(text: string): void {
  clearNode(outputEl);
  outputEl.classList.remove("empty");
  let last = 0;
  for (const m of text.matchAll(PLACEHOLDER_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) outputEl.appendChild(document.createTextNode(text.slice(last, idx)));
    const span = document.createElement("span");
    span.className = "ph";
    span.textContent = m[0];
    outputEl.appendChild(span);
    last = idx + m[0].length;
  }
  if (last < text.length) outputEl.appendChild(document.createTextNode(text.slice(last)));
}

async function runMask(): Promise<void> {
  const text = inputEl.value.trim();
  if (!text) {
    statusEl.textContent = "empty input";
    return;
  }
  runBtn.disabled = true;
  statusEl.textContent = "masking...";
  try {
    const res = await fetch("/api/mask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data: MaskResponse = await res.json();
    renderMasked(data.masked_text);
    statusEl.textContent = `masked ${data.summary.total_masked ?? 0}`;
  } catch (e) {
    statusEl.textContent = `error: ${(e as Error).message}`;
  } finally {
    runBtn.disabled = false;
  }
}

runBtn.addEventListener("click", runMask);
sampleBtn.addEventListener("click", () => {
  inputEl.value = SAMPLE_HAR;
  statusEl.textContent = "";
});
