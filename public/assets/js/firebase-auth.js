// Initialize Firebase Authentication
firebase.auth().onAuthStateChanged(function(user) {
    if (user) {
        // User is signed in
        user.getIdToken().then(function(token) {
            // Store the token
            localStorage.setItem('firebaseToken', token);
            
            // Add token to all AJAX requests
            $.ajaxSetup({
                headers: {
                    'Authorization': 'Bearer ' + token
                }
            });
        });
    } else {
        // User is signed out
        localStorage.removeItem('firebaseToken');
        $.ajaxSetup({
            headers: {
                'Authorization': null
            }
        });
    }
});

// Function to get the current token
function getFirebaseToken() {
    return localStorage.getItem('firebaseToken');
}

// Add token to all fetch requests
function fetchWithAuth(url, options = {}) {
    const token = getFirebaseToken();
    if (!token) {
        return Promise.reject(new Error('No authentication token available'));
    }

    // Merge the authorization header with existing options
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    return fetch(url, {
        ...options,
        headers
    });
}

// Intercepter les formulaires pour ajouter le token
$(document).ready(function() {
    $('form').submit(function(e) {
        const token = getFirebaseToken();
        if (token) {
            // Ajouter un champ caché avec le token
            $(this).append(`<input type="hidden" name="firebase_token" value="${token}">`);
        }
    });
});
