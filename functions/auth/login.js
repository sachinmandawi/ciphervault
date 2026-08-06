export async function onRequest(context) {
  const clientId = context.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return new Response('GITHUB_CLIENT_ID not configured in Cloudflare', { status: 500 });
  }

  // Generate a random state string for security
  const state = crypto.randomUUID();
  
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('scope', 'repo');
  url.searchParams.set('state', state);

  const response = new Response(null, {
    status: 302,
    headers: {
      'Location': url.toString(),
      'Set-Cookie': `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`
    }
  });
  
  return response;
}
