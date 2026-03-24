import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const anonKey = process.env.SUPABASE_ANON_KEY;

/**
 * Optional anon client for flows that must use the public Auth API (e.g. `resetPasswordForEmail`),
 * which is not exposed on the service-role admin client.
 */
export const supabaseAnon =
  supabaseUrl && anonKey ? createClient(supabaseUrl, anonKey) : null;
