export async function onRequestGet(context) {
  const provider = context.params.provider;
  const requestUrl = new URL(context.request.url);
  const code = requestUrl.searchParams.get("code");
  const state = requestUrl.searchParams.get("state");
  const error = requestUrl.searchParams.get("error");

  // 1. Recusar error ou ausência de code e state
  if (error || !code || !state) {
    return new Response("Pedido inválido", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // 2. Exigir o cookie __Host-oauth-tx
  const cookieHeader = context.request.headers.get("Cookie") || "";
  const txCookieMatch = cookieHeader.match(/__Host-oauth-tx=([^;]+)/);
  if (!txCookieMatch) {
    return new Response("Cookie de transação ausente", { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  const txCookie = txCookieMatch[1];

  const sha256 = async (text) => {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  // 3. Calcular resumo e localizar transação
  const txHash = await sha256(txCookie);
  const stateHash = await sha256(state);
  const db = context.env.DB;
  
  const tx = await db.prepare("SELECT * FROM oauth_transactions WHERE id_hash = ?").bind(txHash).first();

  // 4 e 5. Validar estado, apagar transação e impedir reutilização
  if (tx) {
    await db.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(txHash).run();
  }
  
  if (!tx || tx.provider !== provider || tx.expires_at < Math.floor(Date.now() / 1000) || tx.state_hash !== stateHash) {
    return new Response("Transação inválida ou expirada", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const clientId = provider === "google" ? context.env.GOOGLE_CLIENT_ID : context.env.GITHUB_CLIENT_ID;
  const clientSecret = provider === "google" ? context.env.GOOGLE_CLIENT_SECRET : context.env.GITHUB_CLIENT_SECRET;
  const redirectUri = `${context.env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  
  let subject, email, displayName, issuer;

  // 6 e 7. Trocar código e validar identidade
  if (provider === "google") {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret, code,
        code_verifier: tx.code_verifier, redirect_uri: redirectUri, grant_type: "authorization_code"
      })
    });
    if (!tokenResponse.ok) return new Response("Falha na troca de token", { status: 400 });
    
    const tokens = await tokenResponse.json();
    const parts = tokens.id_token.split('.');
    if (parts.length !== 3) return new Response("Formato JWT inválido", { status: 400 });
    
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (header.alg !== "RS256") return new Response("Algoritmo inválido", { status: 400 });
    
    const discovery = await (await fetch("https://accounts.google.com/.well-known/openid-configuration")).json();
    const jwks = await (await fetch(discovery.jwks_uri)).json();
    const jwk = jwks.keys.find(k => k.kid === header.kid);
    if (!jwk) return new Response("Chave não encontrada", { status: 400 });
    
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const signature = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const isValid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
    
    if (!isValid) return new Response("Assinatura inválida", { status: 400 });
    if (!["https://accounts.google.com", "accounts.google.com"].includes(payload.iss) || payload.aud !== clientId) {
      return new Response("Emissor ou audiência inválidos", { status: 400 });
    }
    if (payload.exp < Math.floor(Date.now() / 1000) || payload.nonce !== tx.nonce) {
      return new Response("Token expirado ou nonce inválido", { status: 400 });
    }
    
    subject = payload.sub; email = payload.email; displayName = payload.name; issuer = payload.iss;

  } else {
    // Fluxo GitHub
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri })
    });
    
    const tokens = await tokenResponse.json();
    if (!tokens.access_token || (tokens.token_type || "").toLowerCase() !== "bearer") {
      return new Response("Resposta de token inválida", { status: 400 });
    }
    
    const userResponse = await fetch("https://api.github.com/user", {
      headers: { 
        "Authorization": `Bearer ${tokens.access_token}`, 
        "Accept": "application/vnd.github+json", 
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Oauth-Lab"
      }
    });
    if (!userResponse.ok) return new Response("Falha ao obter perfil", { status: 400 });
    
    const user = await userResponse.json();
    
    // Revogar a autorização da OAuth App
    const revokeResponse = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
      method: "DELETE",
      headers: {
        "Authorization": "Basic " + btoa(`${clientId}:${clientSecret}`),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "Oauth-Lab"
      },
      body: JSON.stringify({ access_token: tokens.access_token })
    });
    if (revokeResponse.status !== 204) return new Response("Falha ao revogar concessão", { status: 400 });
    
    issuer = "https://github.com"; subject = user.id.toString();
    displayName = user.name || user.login; email = user.email || null;
  }

  // 8. Criar a sessão opaca de 8 horas
  const generateRandom = () => {
    const array = new Uint8Array(32); crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  
  const sessionId = generateRandom();
  const sessionHash = await sha256(sessionId);
  const now = Math.floor(Date.now() / 1000);
  
  await db.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(sessionHash, issuer, subject, email, displayName, now + 28800, now).run();

  // 9. Limpar o cookie temporário e criar o cookie de sessão
  const headers = new Headers();
  headers.set("Location", context.env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", `__Host-session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);
  headers.append("Set-Cookie", `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
