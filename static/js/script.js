// Get the password input
const passwordInput = document.getElementById("password");

// Get the button
const toggleButton = document.getElementById("togglePassword");

// Add click event
toggleButton.addEventListener("click", function () {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";
        toggleButton.textContent = "🙈 Hide Password";

    } else {

        passwordInput.type = "password";
        toggleButton.textContent = "👁 Show Password";

    }

});
// Rule elements
const lengthRule = document.getElementById("length");
const upperRule = document.getElementById("uppercase");
const lowerRule = document.getElementById("lowercase");
const numberRule = document.getElementById("number");
const specialRule = document.getElementById("special");

// Strength bar
const strengthFill = document.querySelector(".strength-fill");
const strengthText = document.getElementById("strengthText");
const scoreText = document.getElementById("scoreText");
// Check password while typing
passwordInput.addEventListener("input", function () {

    const password = passwordInput.value;

    let score = 0;

    // Length
    if (password.length >= 8) {
        lengthRule.textContent = "✅ At least 8 characters";
        score++;
    } else {
        lengthRule.textContent = "❌ At least 8 characters";
    }

    // Uppercase
    if (/[A-Z]/.test(password)) {
        upperRule.textContent = "✅ Uppercase letter";
        score++;
    } else {
        upperRule.textContent = "❌ Uppercase letter";
    }

    // Lowercase
    if (/[a-z]/.test(password)) {
        lowerRule.textContent = "✅ Lowercase letter";
        score++;
    } else {
        lowerRule.textContent = "❌ Lowercase letter";
    }

    // Number
    if (/[0-9]/.test(password)) {
        numberRule.textContent = "✅ Number";
        score++;
    } else {
        numberRule.textContent = "❌ Number";
    }

    // Special character
    if (/[^A-Za-z0-9]/.test(password)) {
        specialRule.textContent = "✅ Special character";
        score++;
    } else {
        specialRule.textContent = "❌ Special character";
    }

    // Update strength bar
    const percentage = score * 20;
    scoreText.textContent = `Score: ${percentage} / 100`;
    strengthFill.style.width = percentage + "%";

    // Update color and text
    if (score <= 1) {
        strengthFill.style.background = "red";
        strengthText.textContent = "Weak";
    } else if (score === 2) {
        strengthFill.style.background = "orange";
        strengthText.textContent = "Fair";
    } else if (score === 3) {
        strengthFill.style.background = "gold";
        strengthText.textContent = "Good";
    } else if (score === 4) {
        strengthFill.style.background = "yellowgreen";
        strengthText.textContent = "Strong";
    } else {
        strengthFill.style.background = "green";
        strengthText.textContent = "Very Strong";
    }

});
