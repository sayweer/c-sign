import { json, readCookie } from "./_lib/http.js";
import { SESSION_COOKIE, sessionAccount } from "./_lib/tokens.js";

export async function GET(request: Request): Promise<Response> {
  return json({ account: sessionAccount(readCookie(request, SESSION_COOKIE)) });
}

export async function DELETE(): Promise<Response> {
  return json({ account: null }, 200, { "set-cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` });
}
