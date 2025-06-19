const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  const keycloakUrl = process.env.REACT_APP_KEYCLOAK_URL;
  
  // Proxy all requests to Keycloak
  app.use(
    '/keycloak',
    createProxyMiddleware({
      target: keycloakUrl,
      changeOrigin: true,
      pathRewrite: {
        '^/keycloak': '', // remove /keycloak prefix when forwarding
      },
      onProxyReq: (proxyReq) => {
        // Add CORS headers for all requests
        proxyReq.setHeader('Origin', keycloakUrl);
        proxyReq.setHeader('Access-Control-Allow-Origin', keycloakUrl);
        proxyReq.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        proxyReq.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        proxyReq.setHeader('Access-Control-Allow-Credentials', 'true');
      },
      onProxyRes: (proxyRes) => {
        // Add CORS headers to the response
        proxyRes.headers['Access-Control-Allow-Origin'] = keycloakUrl;
        proxyRes.headers['Access-Control-Allow-Credentials'] = 'true';
      },
      logLevel: 'debug',
    })
  );

  // Handle preflight requests
  app.options('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', keycloakUrl);
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.send(200);
  });
};
