import { createClient } from '@supabase/supabase-js';

const projectUrl = import.meta.env.VITE_SUPABASE_URL?.trim();
const publishableKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY?.trim();
const validUrl = (() => {
  if (!projectUrl) return false;
  try {
    const { protocol, hostname } = new URL(projectUrl);
    return protocol === 'https:' || hostname === 'localhost' || hostname === '127.0.0.1';
  } catch {
    return false;
  }
})();

export const supabaseConfigured = Boolean(validUrl && publishableKey);

export const supabase = supabaseConfigured
  ? createClient(projectUrl, publishableKey, {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: true,
    },
  })
  : null;
