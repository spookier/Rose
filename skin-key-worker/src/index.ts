interface Env {
  SKIN_KEY: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(JSON.stringify({ status: 'ok', service: 'rose-skin-key' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Skin decryption key
    if (url.pathname === '/skin-key' && request.method === 'GET') {
      if (!env.SKIN_KEY) {
        return new Response('Key not configured', { status: 500 });
      }
      return new Response(env.SKIN_KEY, {
        headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};
