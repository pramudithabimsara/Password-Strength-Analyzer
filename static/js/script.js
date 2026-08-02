// Get the password input
const passwordInput = document.getElementById("password");

// Get the button
const toggleButton = document.getElementById("togglePassword");

// Add click event
toggleButton.addEventListener("click", function () {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";
        toggleButton.textContent = "Hide Password";

    } else {

        passwordInput.type = "password";
        toggleButton.textContent = "👁 Show Password";

    }

});

// test