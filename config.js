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

  flowRead:     'https://default0b822811c53c4f5e9444350c2fb3f9.35.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/47d5301442cf4a26aeed97ae54d137ce/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=QvS85nDqyR1aIgU_9Rrl0iqhpS-tReETrf7M91Rccwc',
  flowZachisli: 'https://default0b822811c53c4f5e9444350c2fb3f9.35.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/07dc0b5505724d4bb8ea8bcc01215a35/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=apdLUQR8CW4pzuioH5DaobPAC2XvKeO66mSMsOxijdw',
  flowOtchisli: 'https://default0b822811c53c4f5e9444350c2fb3f9.35.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/41ad71417a524069a8a3e7ec4cc1b6e3/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=pueap1yYjKeRFdipMPKnFZnbo3ZcK9PMw1PRWqmNlpI',
};
