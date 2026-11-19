import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { execFile } from "child_process";
import { existsSync } from "fs";
import path from "path";
import { promisify } from "util";
import { prepareSparql } from "./sparql";

const execFileAsync = promisify(execFile);
const SPARQL_ENDPOINT = process.env.SPARQL_ENDPOINT || "http://localhost:8890/sparql";
const VECTOR_ENDPOINT = process.env.VECTOR_ENDPOINT || "http://localhost:8000/hybrid";

// Tool output is resent to the LLM on every later step, so keep it compact:
// small-tier providers (e.g. Groq free: ~8K tokens/minute) fail on large payloads.
const MAX_SPARQL_ROWS = 25;
const MAX_VALUE_CHARS = 300;

function clip(value: string, max = MAX_VALUE_CHARS, asList = false): string {
  if (value.length <= max) return value;
  // List columns ("a, b, c" or "a; b; c") are cut at a whole item, with a count of
  // the rest, so names never end mid-word ("Crocodil…"). Prose is cut normally.
  const sep = !asList ? "" : value.includes("; ") ? "; " : value.includes(", ") ? ", " : "";
  if (sep) {
    const items = value.split(sep);
    const kept: string[] = [];
    for (const item of items) {
      if ((kept.join(sep) + sep + item).length > max) break;
      kept.push(item);
    }
    if (kept.length) return `${kept.join(sep)} (+${items.length - kept.length} more)`;
  }
  return `${value.slice(0, max)}…`;
}

/**
 * Runs a SPARQL query and returns compact JSON rows (or an "Error ..." string).
 * `maxValueChars` may be a number or a per-column map (default 300 per value).
 */
export async function runSparql(
  query: string,
  maxValueChars: number | Record<string, number> = MAX_VALUE_CHARS,
  listColumns: ReadonlySet<string> = new Set()
): Promise<string> {
  try {
    let safeQuery = prepareSparql(query.trim());
    if (!/limit\s+\d+/i.test(safeQuery)) {
      safeQuery += ` LIMIT ${MAX_SPARQL_ROWS}`;
    }

    const response = await fetch(
      `${SPARQL_ENDPOINT}?query=${encodeURIComponent(safeQuery)}&format=application%2Fsparql-results%2Bjson`,
      { method: "GET", headers: { Accept: "application/sparql-results+json" } }
    );

    if (!response.ok) {
      // Pass Virtuoso's message through: "HTTP 400" alone leaves the model guessing.
      const detail = (await response.text().catch(() => "")).replace(/\s+/g, " ").trim().slice(0, 400);
      throw new Error(`HTTP ${response.status}${detail ? `: ${detail}` : ""}`);
    }

    const data = await response.json();
    const bindings = data?.results?.bindings || [];
    const limitFor = (col: string) =>
      typeof maxValueChars === "number" ? maxValueChars : (maxValueChars[col] ?? MAX_VALUE_CHARS);
    const cleaned = bindings.slice(0, MAX_SPARQL_ROWS).map((row: Record<string, { value: string }>) => {
      const item: Record<string, string> = {};
      for (const [k, v] of Object.entries(row)) item[k] = clip(v.value, limitFor(k), listColumns.has(k));
      return item;
    });

    let jsonOutput = JSON.stringify(cleaned);
    if (bindings.length > MAX_SPARQL_ROWS) {
      jsonOutput += `\n[Notice: Truncated to first ${MAX_SPARQL_ROWS} records out of ${bindings.length} total rows]`;
    }
    return jsonOutput;
  } catch (e: unknown) {
    return `Error executing SPARQL query: ${(e as Error).message}`;
  }
}

export const executeSparqlQuery = tool(async ({ query }) => runSparql(query), {
  name: "execute_sparql_query",
  description: "Execute a SPARQL query against the SOCrates knowledge graph and return results as JSON.",
  schema: z.object({
    query: z.string().describe("The exact SPARQL query to execute"),
  }),
});

export const searchSecurityVectors = tool(
  async ({ query, entity_types, top_k = 5 }) => {
    // 1. Vector HTTP service (the retriever container in Docker).
    let serviceError = "";
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    try {
      const resp = await fetch(VECTOR_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, entity_types, top_k }),
        signal: controller.signal,
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok) {
        const results = (data.results || []).map((r: Record<string, unknown>) => ({
          ...r,
          description: typeof r.description === "string" ? clip(r.description) : r.description,
        }));
        return JSON.stringify(results);
      }
      // The service answered but failed (e.g. SPARQL down). Report it instead of
      // retrying locally, so the agent doesn't mistake an outage for "no results".
      return `Error executing vector search: ${data.error || `HTTP ${resp.status}`}`;
    } catch (e: unknown) {
      serviceError = (e as Error).message;
    } finally {
      clearTimeout(timeoutId);
    }

    // 2. Service unreachable: fall back to the Python CLI in a local checkout.
    const repoRoot = path.resolve(process.cwd(), "..");
    const pythonBin = process.env.VECTOR_PYTHON || path.join(repoRoot, ".venv", "bin", "python");
    if (!existsSync(pythonBin)) {
      return `Error executing vector search: service at ${VECTOR_ENDPOINT} unreachable (${serviceError}) and no local Python found at ${pythonBin}.`;
    }
    try {
      const args = ["-m", "modules.vector.cli", "-q", query, "-k", String(top_k)];
      if (entity_types && entity_types.length > 0) {
        args.push("-t", ...entity_types);
      }

      const { stdout } = await execFileAsync(pythonBin, args, {
        cwd: repoRoot,
        timeout: 10000,
      });

      return stdout.trim();
    } catch (e: unknown) {
      return `Error executing vector search: ${(e as Error).message}`;
    }
  },
  {
    name: "search_security_vectors",
    description:
      "Perform Graph-Augmented Hybrid Retrieval across cybersecurity entities (CVE, CWE, ATT&CK, CAPEC, D3FEND). Mandatory primary tool for conceptual questions, descriptive attack scenarios, threat behaviors, log snippets, or queries lacking exact entity IDs.",
    schema: z.object({
      query: z.string().describe("The descriptive search query, symptom, or scenario"),
      entity_types: z
        .array(z.enum(["cve", "cwe", "attck", "capec", "d3fend"]))
        .optional()
        .describe("Optional entity types to filter by"),
      top_k: z.number().optional().default(5).describe("Max results to return (default: 5)"),
    }),
  }
);
