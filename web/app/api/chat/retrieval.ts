// Deterministic retrieval that runs BEFORE the model on every question.
// Small models skipped or bent prompt-only procedures (no D3FEND search, one
// link check per technique, unchecked "no links" claims). Doing these steps in
// code guarantees them and saves model calls, tokens and rate-limit waits.
import { AIMessage, ToolMessage, type BaseMessage } from "@langchain/core/messages";
import { runSparql, searchSecurityVectors } from "./tools";
import { stepInput, summarizeResult } from "./steps";
import type { ChatEvent } from "../../chat/types";

const TOP_K = 5;
// Countermeasures kept per technique when searching D3FEND by technique name.
const D3FEND_PER_TECHNIQUE = 2;
const TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/;
const G = "http://w3id.org/sepses/graph/";

// Per-column caps for the link check (Groq free tier: ~8K tokens per minute).
const LINK_CHECK_LIMITS: Record<string, number> = {
  name: 80,
  description: 450,
  mitigations: 260,
  countermeasures: 160,
  enterpriseTwin: 40,
  twinCountermeasures: 160,
  capecs: 120,
  cwes: 120,
  software: 160,
  groups: 160,
};

// Columns holding "a, b, c" lists: trimmed at whole items with "(+N more)".
const LIST_COLUMNS = new Set(["mitigations", "countermeasures", "twinCountermeasures", "capecs", "cwes", "software", "groups"]);

type SearchResult = { id: string; name?: string; description?: string; similarity?: number; type?: string };
// The search tool's input schema is narrower than this; it's the shape we call it with.
type SearchTool = { invoke(input: Record<string, unknown>): Promise<unknown> };
const search = searchSecurityVectors as unknown as SearchTool;

/**
 * One query returning, per technique: name, description, official ATT&CK
 * mitigations, D3FEND countermeasures, CAPEC/CWE links, and the malware/tools
 * and groups observed using it (counts + names). Each part is a subquery so the
 * parts don't multiply into each other (T1059 alone has hundreds of users).
 */
export function buildLinkCheckQuery(techniqueIds: string[]): string {
  const V = `VALUES ?t { ${techniqueIds.map((id) => `<http://w3id.org/sepses/resource/attack/${id}>`).join(" ")} }`;
  return `SELECT ?t ?name ?description ?mitigations ?countermeasures ?enterpriseTwin ?twinCountermeasures ?capecs ?cwes ?softwareCount ?software ?groupCount ?groups WHERE {
  ${V}
  OPTIONAL { SELECT ?t (SAMPLE(?n) AS ?name) (SAMPLE(?d) AS ?description) WHERE { ${V} ?t attck:name ?n . OPTIONAL { ?t attck:description ?d } } GROUP BY ?t }
  OPTIONAL { SELECT ?t (GROUP_CONCAT(DISTINCT CONCAT(?mid, " ", ?mn); separator="; ") AS ?mitigations) WHERE { ${V} GRAPH <${G}mitigation2attck> { ?m attck:mitigates ?t } ?m attck:mitreId ?mid ; attck:name ?mn } GROUP BY ?t }
  OPTIONAL { SELECT ?t (GROUP_CONCAT(DISTINCT ?d3; separator=", ") AS ?countermeasures) WHERE { ${V} GRAPH <${G}d3fend2attck> { ?d d3fend:counters ?t } GRAPH <${G}d3fend> { ?d d3fend:d3fend-id ?d3 } } GROUP BY ?t }
  OPTIONAL { SELECT ?t (GROUP_CONCAT(DISTINCT ?eid; separator=", ") AS ?enterpriseTwin) (GROUP_CONCAT(DISTINCT ?ed3; separator=", ") AS ?twinCountermeasures) WHERE { ${V} GRAPH <${G}twin2attck> { ?t attck:enterpriseTwin ?e } ?e attck:techniqueId ?eid . OPTIONAL { GRAPH <${G}d3fend2attck> { ?ed d3fend:counters ?e } GRAPH <${G}d3fend> { ?ed d3fend:d3fend-id ?ed3 } } } GROUP BY ?t }
  OPTIONAL { SELECT ?t (GROUP_CONCAT(DISTINCT ?ci; separator=", ") AS ?capecs) (GROUP_CONCAT(DISTINCT ?wi; separator=", ") AS ?cwes) WHERE { ${V} GRAPH <${G}capec2attck> { ?c capec:hasRelatedAttackPattern ?t } GRAPH <${G}capec> { ?c capec:id ?ci } OPTIONAL { GRAPH <${G}cwe2capec> { ?w cwe:hasCAPEC ?c } GRAPH <${G}cwe> { ?w cwe:id ?wi } } } GROUP BY ?t }
  OPTIONAL { SELECT ?t (COUNT(DISTINCT ?s) AS ?softwareCount) (GROUP_CONCAT(DISTINCT ?sn; separator=", ") AS ?software) WHERE { ${V} GRAPH <${G}software2attck> { ?s attck:uses ?t } ?s attck:name ?sn } GROUP BY ?t }
  OPTIONAL { SELECT ?t (COUNT(DISTINCT ?gr) AS ?groupCount) (GROUP_CONCAT(DISTINCT ?gn; separator=", ") AS ?groups) WHERE { ${V} GRAPH <${G}group2attck> { ?gr attck:uses ?t } ?gr attck:name ?gn } GROUP BY ?t }
}`;
}

function parseResults(text: string): SearchResult[] {
  try {
    return JSON.parse(text.split("\n")[0]) as SearchResult[];
  } catch {
    return [];
  }
}

function clip(value: string | undefined, max: number): string | undefined {
  return value && value.length > max ? `${value.slice(0, max)}…` : value;
}

/**
 * D3FEND countermeasures searched by each technique's name (the name describes the
 * threat far better than the user's whole sentence), top few per technique,
 * de-duplicated, each tagged with the technique(s) it was matched for.
 */
async function countermeasuresPerTechnique(techniques: SearchResult[]): Promise<string> {
  const perTechnique = await Promise.all(
    techniques.map(async (t) => ({
      technique: t.id,
      // D3A- entries are analytic methods (ML, statistics), not countermeasures:
      // fetch one extra so dropping one still leaves enough.
      results: parseResults(
        String(await search.invoke({ query: t.name || t.id, entity_types: ["d3fend"], top_k: D3FEND_PER_TECHNIQUE + 1 }))
      )
        .filter((r) => !r.id.startsWith("D3A-"))
        .slice(0, D3FEND_PER_TECHNIQUE),
    }))
  );
  const merged = new Map<string, SearchResult & { for: string[] }>();
  for (const { technique, results } of perTechnique) {
    for (const r of results) {
      const entry = merged.get(r.id) ?? { id: r.id, name: r.name, description: clip(r.description, 180), similarity: r.similarity, for: [] };
      entry.for.push(technique);
      entry.similarity = Math.max(entry.similarity ?? 0, r.similarity ?? 0);
      merged.set(r.id, entry);
    }
  }
  return JSON.stringify([...merged.values()].sort((a, b) => (b.similarity ?? 0) - (a.similarity ?? 0)));
}

/**
 * Runs the standard retrieval for `question` and returns it as tool-call /
 * tool-result message pairs, so the model sees it exactly as if it had made the
 * calls (and the grounding check counts it). Returns only the first search when
 * the question has nothing to look up (e.g. a follow-up like "are those it?").
 */
export async function preRetrieve(
  question: string,
  send: (event: ChatEvent) => void,
  previousQuestion?: string
): Promise<BaseMessage[]> {
  const messages: BaseMessage[] = [];
  let n = 0;

  // Shows a step in the panel and records it as a tool call + result for the model.
  const step = async (tool: string, args: Record<string, unknown>, label: string, work: () => Promise<string>) => {
    const id = `pre_${++n}`;
    send({ type: "step", step: { id, tool, input: label, status: "running" } });
    const text = await work();
    const result = summarizeResult(tool, text);
    console.log(`[chat] pre-retrieval ${tool}: ${result.summary}`);
    send({ type: "result", id, ...result });
    messages.push(
      new AIMessage({ content: "", tool_calls: [{ id, name: tool, args, type: "tool_call" }] }),
      new ToolMessage({ content: text, tool_call_id: id, name: tool })
    );
    return text;
  };

  send({ type: "status", text: "Searching the knowledge base…" });
  // Unfiltered, so the retriever's no-match cut-off applies: an empty result
  // means the question has nothing to look up, and the remaining steps are skipped.
  const searchFor = async (query: string) => {
    const args = { query, top_k: TOP_K };
    return parseResults(
      await step("search_security_vectors", args, stepInput("search_security_vectors", args), async () =>
        String(await search.invoke(args))
      )
    );
  };
  let topic = question;
  let main = await searchFor(question);
  // A follow-up like "are those it?" has nothing to search for on its own: re-run
  // the retrieval for the previous question so the model answers with evidence.
  if (!main.length && previousQuestion) {
    send({ type: "status", text: "Follow-up question: re-checking the previous topic…" });
    topic = previousQuestion;
    main = await searchFor(previousQuestion);
  }
  if (!main.length) return messages;

  const techniques = main.filter((r) => TECHNIQUE_ID.test(r.id));

  send({ type: "status", text: "Finding countermeasures…" });
  if (techniques.length) {
    const names = techniques.map((t) => t.name || t.id).join("; ");
    await step(
      "search_security_vectors",
      { query: `D3FEND countermeasures per technique: ${names}`, entity_types: ["d3fend"] },
      `Countermeasures per technique: ${names} [d3fend]`,
      () => countermeasuresPerTechnique(techniques)
    );
  } else {
    // No techniques to anchor on: search D3FEND with the question itself.
    const args = { query: topic, entity_types: ["d3fend"], top_k: TOP_K };
    await step("search_security_vectors", args, stepInput("search_security_vectors", args), async () => String(await search.invoke(args)));
  }

  if (techniques.length) {
    send({ type: "status", text: "Checking knowledge-graph links, mitigations and real-world use…" });
    const ids = techniques.map((t) => t.id);
    const query = buildLinkCheckQuery(ids);
    // The model gets a short stand-in for the ~2.5K-char query (it only needs the
    // results); the panel shows the full query.
    await step("execute_sparql_query", { query: `# server-built link check for ${ids.join(" ")}` }, query, () =>
      runSparql(query, LINK_CHECK_LIMITS, LIST_COLUMNS).then((text) =>
        text.startsWith("Error")
          ? text
          : `${text}\n[Note: this link check is complete for ${ids.join(", ")}: it already covers CAPEC, CWE, D3FEND (direct and via Enterprise twin), mitigations, software and groups. Do not query these links again.]`
      )
    );
  }
  return messages;
}
