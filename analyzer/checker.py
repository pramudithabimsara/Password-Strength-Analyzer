import re
from pathlib import Path

from analyzer.entropy import calculate_entropy


# ============================================================
# LOAD COMMON PASSWORDS
# ============================================================

COMMON_PASSWORDS_FILE = Path(__file__).parent / "common_passwords.txt"

with open(
    COMMON_PASSWORDS_FILE,
    "r",
    encoding="utf-8",
    errors="ignore"
) as file:

    COMMON_PASSWORDS = {
        line.strip().lower()
        for line in file
        if line.strip()
    }


# ============================================================
# COMMON PASSWORD CHECK
# ============================================================

def is_common_password(password):
    """
    Check whether the password exists
    in the common password database.
    """

    return password.lower() in COMMON_PASSWORDS


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(password):
    """
    Detect common and predictable password patterns.
    """

    patterns = []

    password_lower = password.lower()

    # Repeated characters
    if len(set(password)) == 1 and len(password) >= 4:
        patterns.append("Repeated characters")

    # Sequential numbers
    sequential_numbers = [
        "1234",
        "2345",
        "3456",
        "4567",
        "5678",
        "6789",
        "7890"
    ]

    for sequence in sequential_numbers:
        if sequence in password:
            patterns.append("Sequential numbers")
            break

    # Sequential letters
    sequential_letters = [
        "abcd",
        "bcde",
        "cdef",
        "defg",
        "efgh",
        "fghi",
        "ghij",
        "hijk",
        "ijkl",
        "jklm",
        "klmn",
        "lmno",
        "mnop",
        "nopq",
        "opqr",
        "pqrs",
        "qrst",
        "rstu",
        "stuv",
        "tuvw",
        "uvwx",
        "vwxy",
        "wxyz"
    ]

    for sequence in sequential_letters:
        if sequence in password_lower:
            patterns.append("Sequential letters")
            break

    # Keyboard patterns
    keyboard_patterns = [
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "qwert",
        "asdf",
        "zxcv"
    ]

    for pattern in keyboard_patterns:
        if pattern in password_lower:
            patterns.append("Keyboard pattern")
            break

    # Year patterns
    for year in range(1950, 2031):
        if str(year) in password:
            patterns.append("Year pattern")
            break

    return patterns


# ============================================================
# CRACK TIME ESTIMATION
# ============================================================
def generate_recommendations(password, results):
    """
    Generate security recommendations based on
    password characteristics and detected weaknesses.
    """

    recommendations = []

    # Password length
    if results["length"] < 8:
        recommendations.append(
            "Use at least 8 characters."
        )

    elif results["length"] < 12:
        recommendations.append(
            "Consider using at least 12 characters."
        )

    # Character variety
    if not results["has_uppercase"]:
        recommendations.append(
            "Add uppercase letters."
        )

    if not results["has_lowercase"]:
        recommendations.append(
            "Add lowercase letters."
        )

    if not results["has_number"]:
        recommendations.append(
            "Add numbers."
        )

    if not results["has_special"]:
        recommendations.append(
            "Add special characters such as !, @, #, or $."
        )

    # Common password
    if results["is_common"]:
        recommendations.append(
            "Avoid using common passwords."
        )

    # Predictable patterns
    if "Repeated characters" in results["patterns"]:
        recommendations.append(
            "Avoid repeating the same character."
        )

    if "Sequential numbers" in results["patterns"]:
        recommendations.append(
            "Avoid sequential numbers such as 1234 or 5678."
        )

    if "Sequential letters" in results["patterns"]:
        recommendations.append(
            "Avoid sequential letters such as abcd."
        )

    if "Keyboard pattern" in results["patterns"]:
        recommendations.append(
            "Avoid keyboard patterns such as qwerty or asdf."
        )

    if "Year pattern" in results["patterns"]:
        recommendations.append(
            "Avoid predictable years such as 2024, 2025, or 2026."
        )

    # No problems found
    if not recommendations:
        recommendations.append(
            "No obvious security weaknesses detected."
        )

    return recommendations
def estimate_crack_time(entropy):
    """
    Estimate brute-force cracking time.

    Assumption:
    10 billion guesses per second for an offline attack.
    """

    guesses_per_second = 10_000_000_000

    possible_guesses = 2 ** entropy

    seconds = possible_guesses / guesses_per_second

    if seconds < 1:
        return "Less than a second"

    if seconds < 60:
        return f"{seconds:.1f} seconds"

    minutes = seconds / 60

    if minutes < 60:
        return f"{minutes:.1f} minutes"

    hours = minutes / 60

    if hours < 24:
        return f"{hours:.1f} hours"

    days = hours / 24

    if days < 365:
        return f"{days:.1f} days"

    years = days / 365

    if years < 1_000_000:
        return f"{years:.1f} years"

    return "Over 1 million years"


# ============================================================
# PASSWORD ANALYZER
# ============================================================

def analyze_password(password):

    # --------------------------------------------------------
    # Basic password characteristics
    # --------------------------------------------------------

    results = {
        "length": len(password),

        "has_uppercase": bool(
            re.search(r"[A-Z]", password)
        ),

        "has_lowercase": bool(
            re.search(r"[a-z]", password)
        ),

        "has_number": bool(
            re.search(r"[0-9]", password)
        ),

        "has_special": bool(
            re.search(r"[^A-Za-z0-9]", password)
        )
    }

    # --------------------------------------------------------
    # Base score
    # Maximum = 100
    # --------------------------------------------------------

    score = 0

    if results["length"] >= 8:
        score += 20

    if results["has_uppercase"]:
        score += 20

    if results["has_lowercase"]:
        score += 20

    if results["has_number"]:
        score += 20

    if results["has_special"]:
        score += 20

    # --------------------------------------------------------
    # Common password detection
    # --------------------------------------------------------

    results["is_common"] = is_common_password(password)

    # --------------------------------------------------------
    # Predictable pattern detection
    # --------------------------------------------------------

    results["patterns"] = detect_patterns(password)

    # --------------------------------------------------------
    # SECURITY SCORE DEDUCTIONS
    # --------------------------------------------------------

    if results["is_common"]:
        score -= 40

    for pattern in results["patterns"]:

        if pattern == "Repeated characters":
            score -= 25

        elif pattern == "Sequential numbers":
            score -= 20

        elif pattern == "Sequential letters":
            score -= 20

        elif pattern == "Keyboard pattern":
            score -= 20

        elif pattern == "Year pattern":
            score -= 15

    # Prevent negative scores
    score = max(0, score)

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    results["score"] = score

    # --------------------------------------------------------
    # Password strength
    # --------------------------------------------------------

    if score <= 20:
        results["strength"] = "Very Weak"

    elif score <= 40:
        results["strength"] = "Weak"

    elif score <= 60:
        results["strength"] = "Fair"

    elif score <= 75:
        results["strength"] = "Good"

    elif score <= 90:
        results["strength"] = "Strong"

    else:
        results["strength"] = "Very Strong"

    # --------------------------------------------------------
    # Entropy
    # --------------------------------------------------------

    results["entropy"] = calculate_entropy(password)

    # --------------------------------------------------------
    # Estimated crack time
    # --------------------------------------------------------

    results["crack_time"] = estimate_crack_time(
        results["entropy"]
    )

    results["recommendations"] = generate_recommendations(
        password,
        results
    )

    return results