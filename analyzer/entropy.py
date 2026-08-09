import math


def calculate_entropy(password):
    """
    Calculate the estimated entropy of a password in bits.
    """

    if not password:
        return 0

    character_set_size = 0

    # Lowercase letters
    if any(char.islower() for char in password):
        character_set_size += 26

    # Uppercase letters
    if any(char.isupper() for char in password):
        character_set_size += 26

    # Numbers
    if any(char.isdigit() for char in password):
        character_set_size += 10

    # Special characters
    if any(not char.isalnum() for char in password):
        character_set_size += 32

    entropy = len(password) * math.log2(character_set_size)

    return round(entropy, 2)