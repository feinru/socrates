import { NextRequest, NextResponse } from "next/server";
import { AIMessage, HumanMessage, SystemMessage } from "@langchain/core/messages";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { SYSTEM_PROMPT } from "./prompt";
import { executeSparqlQuery, searchSecurityVectors } from "./tools";
import { progressNotifier } from "./retry";
import { createModel, describeError, runAgent } from "./agent";
import type { ChatEvent } from "../../chat/types";

const MAX_HISTORY_MESSAGES = 12;
// Earlier reports are long; cap total history size so each LLM call stays small.
const HISTORY_CHAR_BUDGET = Number(process.env.HISTORY_CHAR_BUDGET || 8000);

export async function POST(req: NextRequest) {
  try {
    const { messages, message } = await req.json();

    let inputMessages: (HumanMessage | AIMessage)[] = [];
    if (messages && Array.isArray(messages)) {
      // Drop UI-only messages (the canned greeting and client-side "Error: ..."
      // notices): they were never said by the model and only add noise.
      const history = (messages as { id?: string; role: string; content: unknown }[]).filter(
        (m) =>
          typeof m.content === "string" &&
          m.id !== "init" &&
          !(m.role !== "user" && (m.content as string).startsWith("Error: "))
      );
      // Bound the context: reports are long and the full history is resent each turn.
      let recent = history.slice(-MAX_HISTORY_MESSAGES);
      // Keep the newest messages within the character budget (always keep the last one).
      let used = 0;
      let keepFrom = recent.length;
      for (let i = recent.length - 1; i >= 0; i--) {
        used += (recent[i].content as string).length;
        if (used > HISTORY_CHAR_BUDGET && i < recent.length - 1) break;
        keepFrom = i;
      }
      recent = recent.slice(keepFrom);
      // The conversation must start with a user turn.
      while (recent.length && recent[0].role !== "user") recent = recent.slice(1);
      inputMessages = recent.map((m) =>
        m.role === "user" ? new HumanMessage(m.content as string) : new AIMessage(m.content as string)
      );
      if (!inputMessages.length) {
        return NextResponse.json({ error: "No user message found" }, { status: 400 });
      }
    } else if (message) {
      inputMessages = [new HumanMessage(message)];
    } else {
      return NextResponse.json({ error: "Message or messages array is required" }, { status: 400 });
    }

    const created = createModel();
    if ("error" in created) {
      return NextResponse.json({ error: created.error }, { status: 500 });
    }
    const { llm, label } = created;
    console.log(`[chat] using ${label}`);

    const agent = createReactAgent({
      llm,
      tools: [executeSparqlQuery, searchSecurityVectors],
      prompt: new SystemMessage(SYSTEM_PROMPT),
    });

    // Stream progress to the browser as NDJSON: one ChatEvent per line.
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        const send = (event: ChatEvent) => controller.enqueue(encoder.encode(JSON.stringify(event) + "\n"));
        await progressNotifier.run((text) => send({ type: "status", text }), async () => {
          try {
            await runAgent(agent, llm, inputMessages, send);
          } catch (error) {
            const { status, error: message } = describeError(error);
            console.error(`[chat] failed (${status}):`, (error as Error)?.message || error);
            send({ type: "error", error: message });
          } finally {
            controller.close();
          }
        });
      },
    });
    return new Response(stream, {
      headers: {
        "Content-Type": "application/x-ndjson; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
      },
    });
  } catch (error: unknown) {
    const { status, error: message } = describeError(error);
    console.error(`[chat] failed (${status}):`, (error as Error)?.message || error);
    return NextResponse.json({ error: message }, { status });
  }
}
