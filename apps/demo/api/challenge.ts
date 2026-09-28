import { issueChallenge } from "./_lib/tokens.js";
import { json, rateLimited } from "./_lib/http.js";

export const STATEMENT = "Sign in to the C-Sign demo.";

export async function GET(request: Request): Promise<Response> {
  if (rateLimited(request, 60)) return json({ error: "Too many requests" }, 429);
  const { nonce, issuedAt, token } = issueChallenge();
  return json({ statement: STATEMENT, nonce, issuedAt, token });
}
