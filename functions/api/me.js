export async function onRequestGet(context) {
  const cookieHeader = context.request.headers.get("Cookie") || "";
  const sessionMatch = cookieHeader.match(/__Host-session=([^;]+)/);

  if (!sessionMatch) {
    return new Response("Não autorizado", { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  const sessionId = sessionMatch[1];
  const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionId));
  const sessionHash = btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const session = await context.env.DB.prepare("SELECT * FROM sessions WHERE id_hash = ?").bind(sessionHash).first();

  if (!session || session.expires_at < Math.floor(Date.now() / 1000)) {
    return new Response("Sessão inválida ou expirada", { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  return Response.json(
    { email: session.email, displayName: session.display_name },
    { headers: { "Cache-Control": "no-store" } }
  );
}
