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
const entropyText = document.getElementById("entropyText");
const commonPasswordText =
    document.getElementById("commonPasswordText");
    const patternsText =
    document.getElementById("patternsText");
const crackTimeText = document.getElementById("crackTimeText");
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
        numberRule.textContent = "✅ Number";//test
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
// Send password to Flask backend
async function analyzeWithBackend(password) {

    try {

        const response = await fetch("/analyze", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                password: password
            })
        });

        const result = await response.json();

        console.log("Backend result:", result);

        return result;

    } catch (error) {

        console.error("Backend error:", error);

    }
}
analyzeWithBackend();
// Analyze button
const analyzeButton = document.getElementById("analyzeButton");

analyzeButton.addEventListener("click", async function () {

    const password = passwordInput.value;

    if (password === "") {
        alert("Please enter a password first.");
        return;
    }

    const result = await analyzeWithBackend(password);

    if (!result) {
        return;
    }

    // Update password rules
    lengthRule.textContent = result.length >= 8
        ? "✅ At least 8 characters"
        : "❌ At least 8 characters";

    upperRule.textContent = result.has_uppercase
        ? "✅ Uppercase letter"
        : "❌ Uppercase letter";

    lowerRule.textContent = result.has_lowercase
        ? "✅ Lowercase letter"
        : "❌ Lowercase letter";

    numberRule.textContent = result.has_number
        ? "✅ Number"
        : "❌ Number";

    specialRule.textContent = result.has_special
        ? "✅ Special character"
        : "❌ Special character";


    // Update score
    scoreText.textContent = `Score: ${result.score} / 100`;
    entropyText.textContent = `Entropy: ${result.entropy} bits`;
    crackTimeText.textContent =
    `Estimated crack time: ${result.crack_time}`;
    if (result.is_common) {
    commonPasswordText.textContent =
        "⚠️ Common password detected! Choose a more unique password.";
} else {
    commonPasswordText.textContent =
        "✅ This password was not found in the common password list.";
}
if (result.patterns.length > 0) {
    patternsText.textContent =
        `⚠️ Predictable patterns: ${result.patterns.join(", ")}`;
} else {
    patternsText.textContent =
        "✅ No obvious predictable patterns detected.";
}


    // Update strength
    strengthText.textContent = result.strength;


    // Update strength bar
    strengthFill.style.width = result.score + "%";


    // Update strength bar color
    if (result.score <= 20) {

        strengthFill.style.background = "red";

    } else if (result.score <= 40) {

        strengthFill.style.background = "orange";

    } else if (result.score <= 60) {

        strengthFill.style.background = "gold";

    } else if (result.score <= 80) {

        strengthFill.style.background = "yellowgreen";

    } else {

        strengthFill.style.background = "green";

    }

});