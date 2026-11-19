export function normalizeMarkdown(text: string): string {
  if (!text) return "";

  let cleaned = text;

  cleaned = cleaned.replace(/([^\n])```/g, "$1\n\n```");
  cleaned = cleaned.replace(/```([a-zA-Z0-9_-]+)[ \t]+(?=[^\r\n])/g, "```$1\n");
  cleaned = cleaned.replace(/```\s*\n\s*```/g, "");

  cleaned = cleaned.replace(
    /```(?:text|markdown)?\s*\n([\s\S]*?\*\*[0-9]+[\s\S]*?)```/g,
    "$1"
  );

  cleaned = cleaned.replace(/\n {4,}(#{1,6}\s|\*\*)/g, "\n$1");

  cleaned = cleaned.replace(
    /\n\s*[*+-]\s+\*\*(CWE(?: Name)?|CAPEC(?: Name)?|ATT&CK(?: Technique)?|Technique|Impact|Weakness|Details|SOC (?:Threat Context|Perspective)|Severity|Base Score|Published)\*\*/gi,
    "\n    - **$1**"
  );

  const lines = cleaned.split("\n");
  const result: string[] = [];
  let inCategoryBullet = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isCategoryHeader = /^\s*[*+-]\s+\*\*[^*]+(?::\*\*|\*\*:)\s*$/.test(line);
    const isBullet = /^\s*[*+-]\s+/.test(line);
    const isIndentedBullet = /^\s{2,}[*+-]\s+/.test(line);

    if (isCategoryHeader) {
      inCategoryBullet = true;
      result.push(line.trimStart());
    } else if (isBullet) {
      if (isIndentedBullet) {
        result.push(line);
      } else if (inCategoryBullet) {
        result.push("    " + line.trimStart());
      } else {
        result.push(line);
      }
    } else {
      if (line.trim().length > 0 && !line.startsWith(" ")) {
        inCategoryBullet = false;
      }
      result.push(line);
    }
  }

  cleaned = result.join("\n");
  cleaned = cleaned.replace(/(\w+)\s+:\s+:\s*(\w+)/g, "$1::$2");

  return cleaned.trim();
}

export function formatUriLabel(href: string): string {
  if (!href) return "";
  if (href.includes("w3id.org/sepses/vocab/ref/")) {
    const parts = href.split("ref/");
    return parts[1] || href;
  }
  if (href.includes("w3id.org/sepses/graph/")) {
    const parts = href.split("graph/");
    return `graph:${parts[1] || href}`;
  }
  if (href.includes("w3id.org/sepses/resource/")) {
    const parts = href.split("resource/");
    return parts[1] || href;
  }
  return href;
}
