document.addEventListener("DOMContentLoaded", fetchProfile);

function fetchProfile() {
    fetch("/api/profile-data")
        .then(response => response.json())
        .then(data => {
            const profileInfo = document.getElementById("profile-info");
            profileInfo.innerHTML = `
                <h2>${data.name}</h2>
                <p>Email: ${data.email}</p>
                <p>Username: ${data.preferred_username}</p>
            `;
        })
        .catch(error => {
            console.error("Error fetching profile data:", error);
            document.getElementById("profile-info").innerText = "Error loading profile.";
        });
}

function goToDashboard() {
    window.location.href = "/dashboard";
}

function logout() {
    window.location.href = "/logout";
}
