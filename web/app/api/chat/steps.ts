// Turns raw tool calls and results into short, human-readable process steps.

const PREVIEW_CHARS = 2000;

export function stepInput(tool: string, args: Record<string, unknown>): string {
  if (tool === "execute_sparql_query") return String(args.query ?? "").trim();
  if (tool === "search_security_vectors") {
    const types = Array.isArray(args.entity_types) && args.entity_types.length ? ` [${args.entity_types.join(", ")}]` : "";
    return `${String(args.query ?? "")}${types}`;
  }
  return JSON.stringify(args);
}

export function summarizeResult(
  tool: string,
  text: string
): { status: "done" | "error"; summary: string; preview: string } {
  if (/^Error/i.test(text)) {
    return { status: "error", summary: text.replace(/\s+/g, " ").slice(0, 200), preview: "" };
  }
  // Tool output is a one-line JSON array, possibly followed by "[Notice: ...]" /
  // "[Note: ...]" lines (which contain brackets of their own).
  let rows: Record<string, unknown>[] = [];
  try {
    rows = JSON.parse(text.split("\n")[0]);
  } catch {
    return { status: "done", summary: "Result received", preview: text.slice(0, PREVIEW_CHARS) };
  }
  const truncated = /\[Notice: Truncated/.test(text) ? " (truncated)" : "";

  if (tool === "search_security_vectors") {
    if (!rows.length) return { status: "done", summary: "No matching entities", preview: "" };
    const ids = rows.map((r) => String(r.id));
    const preview = rows
      .map((r) => {
        const sim = Number(r.similarity) > 0 ? `sim ${Number(r.similarity).toFixed(2)}` : "graph-linked";
        return `${r.id}  ${r.name ?? ""}  (${sim})`;
      })
      .join("\n");
    return { status: "done", summary: `${rows.length} results: ${ids.join(", ")}`, preview };
  }

  if (!rows.length) return { status: "done", summary: "0 rows (no matches in the knowledge graph)", preview: "" };
  const preview = rows
    .slice(0, 15)
    .map((r) =>
      Object.entries(r)
        // Long prose (technique descriptions) would crowd out the other rows; the
        // model still receives it in full.
        .filter(([k]) => k !== "description")
        .map(([k, v]) => {
          const val = String(v ?? "");
          // Show URIs by their local name (…/attack/T1078 -> T1078); keep text as is.
          const short = /^https?:\/\//.test(val) ? val.split(/[/#]/).pop() : val;
          const shown = short && short.length > 160 ? `${short.slice(0, 160)}…` : short;
          return `${k}: ${shown || "–"}`;
        })
        .join(" | ")
    )
    .join("\n");
  return {
    status: "done",
    summary: `${rows.length} row${rows.length === 1 ? "" : "s"}${truncated}`,
    preview: preview.slice(0, PREVIEW_CHARS),
  };
}
