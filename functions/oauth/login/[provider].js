export async function onRequestGet(context) {
  const provider = context.params.provider;
  
  // 1. Aceitar somente google ou github
  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  // 2. Valores aleatórios e resumos (Web Crypto)
  const generateRandom = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const sha256 = async (text) => {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const txId = generateRandom();
  const state = generateRandom();
  const codeVerifier = generateRandom();
  const nonce = provider === "google" ? generateRandom() : null;

  const codeChallenge = await sha256(codeVerifier);
  const txHash = await sha256(txId);
  const stateHash = await sha256(state);
  const expiresAt = Math.floor(Date.now() / 1000) + 600; // expira em 10 minutos

  // 3. Gravar a transação no D1
  await context.env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(txHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

  // 4. Montar o pedido de autorização
  const redirectUri = `${context.env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const clientId = provider === "google" ? context.env.GOOGLE_CLIENT_ID : context.env.GITHUB_CLIENT_ID;
  
  const authUrl = new URL(provider === "google" ? "https://accounts.google.com/o/oauth2/v2/auth" : "https://github.com/login/oauth/authorize");
  
  // Comuns aos dois provedores
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  
  // Somente no Google
  if (provider === "google") {
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("nonce", nonce);
  }

  // 5. Criar cookie temporário e responder com redirecionamento 302
  return new Response(null, {
    status: 302,
    headers: {
      "Location": authUrl.toString(),
      "Set-Cookie": `__Host-oauth-tx=${txId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
      "Cache-Control": "no-store"
    }
  });
}
