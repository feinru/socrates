// Makes model-written SPARQL acceptable to Virtuoso before sending it:
// - adds standard PREFIX declarations the query uses but forgot to declare
// - moves DEFINE pragmas before all PREFIX lines (Virtuoso rejects the other order)
// Each failed query costs an agent step and, on small-tier providers, rate-limit time.

export const STANDARD_PREFIXES: Record<string, string> = {
  cve: "http://w3id.org/sepses/vocab/ref/cve#",
  cpe: "http://w3id.org/sepses/vocab/ref/cpe#",
  cwe: "http://w3id.org/sepses/vocab/ref/cwe#",
  capec: "http://w3id.org/sepses/vocab/ref/capec#",
  attck: "http://w3id.org/sepses/vocab/ref/attack#",
  icsa: "http://w3id.org/sepses/vocab/ref/icsa#",
  epss: "http://w3id.org/sepses/vocab/ref/epss#",
  d3fend: "http://d3fend.mitre.org/ontologies/d3fend.owl#",
  rdfs: "http://www.w3.org/2000/01/rdf-schema#",
  rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
  xsd: "http://www.w3.org/2001/XMLSchema#",
};

const DEFINE_RE = /^[ \t]*DEFINE[ \t]+[^\n]*$/gim;
const PREFIX_RE = /PREFIX\s+([A-Za-z][\w-]*)?:\s*<[^>]*>/gi;

export function prepareSparql(query: string): string {
  const defines = (query.match(DEFINE_RE) ?? []).map((d) => d.trim());
  let body = query.replace(DEFINE_RE, "");

  const declared = new Map<string, string>();
  for (const m of body.matchAll(PREFIX_RE)) declared.set(m[1] ?? "", m[0].trim());
  body = body.replace(PREFIX_RE, "").trim();

  // Strip IRIs and string literals so "http://" or text like "note:" isn't read as a prefix.
  const scan = body.replace(/<[^>\s]*>/g, " ").replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, " ");
  for (const [name, iri] of Object.entries(STANDARD_PREFIXES)) {
    if (!declared.has(name) && new RegExp(`(^|[^\\w:])${name}:`).test(scan)) {
      declared.set(name, `PREFIX ${name}: <${iri}>`);
    }
  }

  return [...defines, ...declared.values(), body].join("\n");
}
