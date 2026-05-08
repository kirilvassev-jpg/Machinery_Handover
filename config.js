/**
 * Client-side application configuration.
 *
 * These values are intentionally client-visible (Azure AD public client,
 * Supabase publishable key). They must NOT contain service-role keys,
 * Power Automate URLs, or any other server-side secrets.
 *
 * To protect this file in a real deployment:
 *   - Add `config.js` to .gitignore and use a build-time substitution, OR
 *   - Serve it from a backend endpoint that reads from environment variables.
 */
const APP_CONFIG = {
  proxyUrl:      'https://wcsdjfsohqanxcppcvvk.supabase.co/functions/v1/proxy',
  functionScope: 'api://0afb663f-c74b-4cc5-9a32-30cbf172b0de/user_impersonation',

  supabaseUrl:   'https://wcsdjfsohqanxcppcvvk.supabase.co',
  supabaseKey:   'sb_publishable_aMxRatJ2BJxE5vQIhffing_8_zMpBDO',

  msal: {
    clientId:   '62029787-9853-404f-9a43-eff6e9762d13',
    tenantId:   '0b822811-c53c-4f5e-9444-350c2fb3f935',
  },
};
