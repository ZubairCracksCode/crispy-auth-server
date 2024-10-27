function goToProfile() {
    window.location.href = "/profile";
}

function logout() {
    localStorage.removeItem('access_token');
    window.location.href = "/logout";
}
