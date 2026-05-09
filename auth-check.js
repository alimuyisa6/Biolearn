const SUPABASE_URL = 'https://bhhndmcqjibodbfmbrpj.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJoaG5kbWNxamlib2RiZm1icnBqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY0ODI3MzIsImV4cCI6MjA5MjA1ODczMn0.aXTyrqWOECUHccOLcrwERPWTWu46fsGxYwkt-5xbrl8';

const supabase = window.supabase?.createClient?.(SUPABASE_URL, SUPABASE_ANON_KEY) ?? null;
if (!supabase) console.error('Supabase client not loaded');

async function getSession() {
    const cached = sessionStorage.getItem('biolearn_session');
    if (cached) {
        try {
            const parsed = JSON.parse(cached);
            if (parsed.timestamp && (Date.now() - parsed.timestamp < 300000)) {
                return parsed.session;
            }
        } catch (e) {}
    }

    const { data: { session } } = await supabase.auth.getSession();
    
    if (session) {
        sessionStorage.setItem('biolearn_session', JSON.stringify({ session, timestamp: Date.now() }));
    } else {
        sessionStorage.removeItem('biolearn_session');
    }
    
    return session;
}

supabase.auth.onAuthStateChange((event) => {
    if (event === 'SIGNED_OUT') sessionStorage.removeItem('biolearn_session');
});

const pageCache = { siteSections: null, resources: null, groupedResources: null };

export { supabase, getSession, pageCache };
