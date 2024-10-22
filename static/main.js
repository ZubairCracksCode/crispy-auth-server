function login() {
    window.location.href = "/login";
}

function fetchProfile() {
    fetch('/profile')
        .then(response => response.json())
        .then(data => {
            document.getElementById('output').innerText = JSON.stringify(data, null, 2);
        });
}

function callSchool2Api() {
    fetch('/school2-api')
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error("Unauthorized");
            }
        })
        .then(data => {
            document.getElementById('output').innerText = JSON.stringify(data, null, 2);
        })
        .catch(err => {
            document.getElementById('output').innerText = err.message;
        });
}

function logout() {
    window.location.href = "/logout";
}

// function getToken() {
//     const username = document.getElementById('username').value;
//     const password = document.getElementById('password').value;

//     fetch('/get-token', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json'
//             },
//             body: JSON.stringify({
//                 username: username,
//                 password: password
//             })
//         })
//         .then(response => response.json())
//         .then(data => {
//             if (data.access_token) {
//                 // Store token in session storage
//                 sessionStorage.setItem('access_token', data.access_token);
//                 document.getElementById('output').innerText = 'Logged in successfully!';
//             } else {
//                 document.getElementById('output').innerText = 'Login failed: ' + data.error;
//             }
//         })
//         .catch(err => {
//             document.getElementById('output').innerText = 'Error: ' + err.message;
//         });
// }

// function fetchProfile() {
//     const token = sessionStorage.getItem('access_token');

//     fetch('/profile', {
//             headers: {
//                 'Authorization': 'Bearer ' + token
//             }
//         })
//         .then(response => response.json())
//         .then(data => {
//             document.getElementById('output').innerText = JSON.stringify(data, null, 2);
//         })
//         .catch(err => {
//             document.getElementById('output').innerText = 'Error: ' + err.message;
//         });
// }

// function callSchool2Api() {
//     const token = sessionStorage.getItem('access_token');

//     fetch('/school2-api', {
//             headers: {
//                 'Authorization': 'Bearer ' + token
//             }
//         })
//         .then(response => {
//             if (response.ok) {
//                 return response.json();
//             } else {
//                 throw new Error("Unauthorized");
//             }
//         })
//         .then(data => {
//             document.getElementById('output').innerText = JSON.stringify(data, null, 2);
//         })
//         .catch(err => {
//             document.getElementById('output').innerText = err.message;
//         });
// }

// function logout() {
//     sessionStorage.removeItem('access_token');
//     fetch('/logout')
//         .then(() => {
//             document.getElementById('output').innerText = 'Logged out successfully!';
//         })
//         .catch(err => {
//             document.getElementById('output').innerText = 'Error: ' + err.message;
//         });
// }