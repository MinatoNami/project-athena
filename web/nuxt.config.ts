export default defineNuxtConfig({
  compatibilityDate: '2026-08-19',
  ssr: true,
  devtools: { enabled: false },
  css: ['~/assets/css/main.css'],

  app: {
    head: {
      titleTemplate: (title?: string) => (title ? `${title} · Athena` : 'Athena'),
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
      htmlAttrs: { lang: 'en' },
    },
  },

  runtimeConfig: {
    // Server-only. The browser never receives a value that can reach core directly.
    athenaApiUrl: process.env.NUXT_ATHENA_API_URL || 'http://127.0.0.1:8000',
    sessionSecretFile: process.env.NUXT_SESSION_SECRET_FILE || '',
    public: {
      appName: process.env.NUXT_PUBLIC_APP_NAME || 'Athena',
    },
  },

  nitro: {
    // The strict CSP is viable because the deployment is entirely self-contained:
    // no CDN, no external fonts, no third-party analytics.
    routeRules: {
      '/**': {
        headers: {
          'Content-Security-Policy':
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; " +
            "base-uri 'none'; object-src 'none'; form-action 'self'",
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'same-origin',
          'X-Frame-Options': 'DENY',
        },
      },
    },
  },

  typescript: { strict: true },
})
