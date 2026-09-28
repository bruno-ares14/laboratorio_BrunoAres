export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin");
  
  if (origin !== context.env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const cookieHeader = context.request.headers.get("Cookie") || "";
  const sessionMatch = cookieHeader.match(/__Host-session=([^;]+)/);

  const headers = new Headers();
  headers.set("Cache-Control", "no-store");
  // Expira o cookie independentemente de o encontrar na base de dados ou não
  headers.append("Set-Cookie", `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);

  if (sessionMatch) {
    const sessionId = sessionMatch[1];
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionId));
    const sessionHash = btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    // Remove a sessão do D1
    await context.env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(sessionHash).run();
  }

  // Redireciona de volta para a raiz após o logout
  headers.set("Location", context.env.PUBLIC_BASE_URL);
  return new Response(null, { status: 302, headers });
}
