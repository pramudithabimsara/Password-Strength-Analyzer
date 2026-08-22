// =====================================================
// PASSWORD ANALYZER
// =====================================================

const passwordInput =
    document.getElementById("password");

const toggleButton =
    document.getElementById("togglePassword");


// =====================================================
// SHOW / HIDE PASSWORD
// =====================================================

if (toggleButton && passwordInput) {

    toggleButton.addEventListener(
        "click",
        function () {

            if (passwordInput.type === "password") {

                passwordInput.type = "text";

                toggleButton.textContent =
                    "🙈 Hide Password";

            } else {

                passwordInput.type = "password";

                toggleButton.textContent =
                    "👁 Show Password";
            }
        }
    );
}


// =====================================================
// PASSWORD RULE ELEMENTS
// =====================================================

const lengthRule =
    document.getElementById("length");

const upperRule =
    document.getElementById("uppercase");

const lowerRule =
    document.getElementById("lowercase");

const numberRule =
    document.getElementById("number");

const specialRule =
    document.getElementById("special");


// =====================================================
// RESULT ELEMENTS
// =====================================================

const strengthFill =
    document.querySelector(".strength-fill");

const strengthText =
    document.getElementById("strengthText");

const scoreText =
    document.getElementById("scoreText");

const entropyText =
    document.getElementById("entropyText");

const commonPasswordText =
    document.getElementById("commonPasswordText");

const patternsText =
    document.getElementById("patternsText");

const recommendationsText =
    document.getElementById("recommendationsText");

const crackTimeText =
    document.getElementById("crackTimeText");


// =====================================================
// LIVE PASSWORD CHECK
// =====================================================

if (passwordInput) {

    passwordInput.addEventListener(
        "input",
        function () {

            const password =
                passwordInput.value;

            let score = 0;


            // Length
            if (password.length >= 8) {

                lengthRule.textContent =
                    "✅ At least 8 characters";

                score++;

            } else {

                lengthRule.textContent =
                    "❌ At least 8 characters";
            }


            // Uppercase
            if (/[A-Z]/.test(password)) {

                upperRule.textContent =
                    "✅ Uppercase letter";

                score++;

            } else {

                upperRule.textContent =
                    "❌ Uppercase letter";
            }


            // Lowercase
            if (/[a-z]/.test(password)) {

                lowerRule.textContent =
                    "✅ Lowercase letter";

                score++;

            } else {

                lowerRule.textContent =
                    "❌ Lowercase letter";
            }


            // Number
            if (/[0-9]/.test(password)) {

                numberRule.textContent =
                    "✅ Number";

                score++;

            } else {

                numberRule.textContent =
                    "❌ Number";
            }


            // Special character
            if (/[^A-Za-z0-9]/.test(password)) {

                specialRule.textContent =
                    "✅ Special character";

                score++;

            } else {

                specialRule.textContent =
                    "❌ Special character";
            }


            // Calculate percentage
            const percentage =
                score * 20;

            scoreText.textContent =
                `Score: ${percentage} / 100`;

            strengthFill.style.width =
                percentage + "%";


            // Strength
            if (score <= 1) {

                strengthFill.style.background =
                    "#dc2626";

                strengthText.textContent =
                    "Weak";

            } else if (score === 2) {

                strengthFill.style.background =
                    "#f97316";

                strengthText.textContent =
                    "Fair";

            } else if (score === 3) {

                strengthFill.style.background =
                    "#eab308";

                strengthText.textContent =
                    "Good";

            } else if (score === 4) {

                strengthFill.style.background =
                    "#84cc16";

                strengthText.textContent =
                    "Strong";

            } else {

                strengthFill.style.background =
                    "#16a34a";

                strengthText.textContent =
                    "Very Strong";
            }
        }
    );
}


// =====================================================
// BACKEND ANALYSIS
// =====================================================

async function analyzeWithBackend(password) {

    try {

        const response =
            await fetch("/analyze", {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    password: password
                })
            });


        const result =
            await response.json();

        return result;

    } catch (error) {

        console.error(
            "Backend error:",
            error
        );

        return null;
    }
}


// =====================================================
// ANALYZE BUTTON
// =====================================================

const analyzeButton =
    document.getElementById("analyzeButton");


if (analyzeButton) {

    analyzeButton.addEventListener(
        "click",
        async function () {

            const password =
                passwordInput.value;


            if (!password) {

                alert(
                    "Please enter a password first."
                );

                return;
            }


            const result =
                await analyzeWithBackend(
                    password
                );


            if (!result) {
                return;
            }


            // Rules
            lengthRule.textContent =
                result.length >= 8
                    ? "✅ At least 8 characters"
                    : "❌ At least 8 characters";

            upperRule.textContent =
                result.has_uppercase
                    ? "✅ Uppercase letter"
                    : "❌ Uppercase letter";

            lowerRule.textContent =
                result.has_lowercase
                    ? "✅ Lowercase letter"
                    : "❌ Lowercase letter";

            numberRule.textContent =
                result.has_number
                    ? "✅ Number"
                    : "❌ Number";

            specialRule.textContent =
                result.has_special
                    ? "✅ Special character"
                    : "❌ Special character";


            // Score
            scoreText.textContent =
                `Score: ${result.score} / 100`;


            entropyText.textContent =
                `Entropy: ${result.entropy} bits`;


            crackTimeText.textContent =
                `Estimated crack time: ${result.crack_time}`;


            // Common password
            if (result.is_common) {

                commonPasswordText.textContent =
                    "⚠️ Common password detected! Choose a more unique password.";

            } else {

                commonPasswordText.textContent =
                    "✅ This password was not found in the common password list.";
            }


            // Patterns
            if (
                result.patterns &&
                result.patterns.length > 0
            ) {

                patternsText.textContent =
                    `⚠️ Predictable patterns: ${result.patterns.join(", ")}`;

            } else {

                patternsText.textContent =
                    "✅ No obvious predictable patterns detected.";
            }


            // Recommendations
            if (
                result.recommendations &&
                result.recommendations.length > 0
            ) {

                recommendationsText.innerHTML =
                    "<strong>🔐 Security Recommendations:</strong><br>" +
                    result.recommendations
                        .map(
                            recommendation =>
                                `• ${recommendation}`
                        )
                        .join("<br>");

            } else {

                recommendationsText.textContent =
                    "✅ No additional recommendations.";
            }


            // Strength
            strengthText.textContent =
                result.strength;


            // Strength bar
            strengthFill.style.width =
                result.score + "%";


            if (result.score <= 20) {

                strengthFill.style.background =
                    "#dc2626";

            } else if (result.score <= 40) {

                strengthFill.style.background =
                    "#f97316";

            } else if (result.score <= 60) {

                strengthFill.style.background =
                    "#eab308";

            } else if (result.score <= 80) {

                strengthFill.style.background =
                    "#84cc16";

            } else {

                strengthFill.style.background =
                    "#16a34a";
            }
        }
    );
}