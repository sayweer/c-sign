// Serves app.ts with node:http. In a framework, mount the two handlers instead.
import { createServer } from "node:http";
import { challenge, verify } from "./app.js";

const PORT = Number(process.env.PORT ?? 8787);

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  let response: Response;
  if (req.method === "GET" && url.pathname === "/challenge") {
    response = challenge();
  } else if (req.method === "POST" && url.pathname === "/verify") {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    response = await verify(new Request(url, { method: "POST", body: Buffer.concat(chunks) }));
  } else {
    response = new Response("Not found", { status: 404 });
  }
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}).listen(PORT, () => console.log(`Relying party on http://localhost:${PORT}`));
