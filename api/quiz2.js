 const MAIN_API = '/api/query';
const QUIZ_API = '/api/quiz2';

async function apiCall(action, params = {}) {
    const token = getToken();
    const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    
    // Actions that go to MAIN_API (navigation, auth, footer, contact, etc.)
    const mainActions = [
        'get_all_site_sections', 'get_site_section',
        'signin', 'signup', 'signout', 'get_user',
        'submit_contact', 'subscribe_newsletter',
        'get_resources', 'get_filter_options'
    ];
    
    // Actions that go to QUIZ_API
    const quizActions = [
        'get_quizzes', 'get_quiz', 'complete_quiz', 
        'add_reaction', 'get_user_progress'
    ];
    
    let endpoint = MAIN_API;
    if (quizActions.includes(action)) {
        endpoint = QUIZ_API;
    }
    
    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify({ action, ...params })
        });
        
        if (res.status === 401) { 
            localStorage.removeItem('sb-token'); 
            localStorage.removeItem('sb-email'); 
            updateMobileNav(); 
            return null; 
        }
        
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || 'Request failed');
        
        // Handle different response formats
        if (endpoint === QUIZ_API) {
            // quiz2.js returns { success: true, data: [...] }
            return json.data !== undefined ? json.data : (json.success ? json.data : json);
        }
        
        // MAIN_API returns { data: ... } or direct array
        return json.data !== undefined ? json.data : json;
        
    } catch (err) { 
        console.error('API Error:', err); 
        return null; 
    }
}
