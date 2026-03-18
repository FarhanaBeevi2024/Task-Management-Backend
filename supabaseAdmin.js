import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl) throw new Error('SUPABASE_URL is required');
if (!serviceKey) throw new Error('SUPABASE_SERVICE_KEY is required');

export const supabaseAdmin = createClient(supabaseUrl, serviceKey);

