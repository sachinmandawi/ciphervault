export async function onRequest(context) {
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  const cookieHeader = context.request.headers.get('Cookie');
  let oauthStateCookie = null;
  if (cookieHeader) {
    const match = cookieHeader.match(/(?:^|;\s*)oauth_state=([^;]*)/);
    if (match) {
      oauthStateCookie = match[1];
    }
  }

  if (!oauthStateCookie || oauthStateCookie !== state) {
    return new Response('Invalid state parameter (CSRF check failed).', { status: 403 });
  }

  if (!code) {
    return new Response('No authorization code provided by GitHub.', { status: 400 });
  }

  const clientId = context.env.GITHUB_CLIENT_ID;
  const clientSecret = context.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return new Response('GitHub OAuth credentials not configured in Cloudflare.', { status: 500 });
  }

  try {
    // Exchange code for token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'CipherVault-Worker'
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        state: state
      })
    });

    const data = await tokenResponse.json();

    if (data.error) {
      return new Response(`OAuth Error: ${data.error_description}`, { status: 400 });
    }

    const accessToken = data.access_token;
    
    // Redirect back to the frontend with the token in the URL hash (fragment).
    // Fragments are NOT sent to the server, so it remains purely client-side secure.
    const redirectUrl = new URL(context.request.url);
    redirectUrl.pathname = '/';
    redirectUrl.search = '';
    redirectUrl.hash = `oauth_token=${accessToken}`;
    
    return Response.redirect(redirectUrl.toString(), 302);
  } catch (err) {
    return new Response(`Internal Server Error: ${err.message}`, { status: 500 });
  }
}
