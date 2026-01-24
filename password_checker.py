#CVNP2646 - Week 2
#Task 2: Password Strength Checker


SPECIALS = set("!@#$%^&*()-_=+[]{}|;:',.<>/?`~\\\"")


def check_password_strength(password: str):
    """
    Rules from assignment:
    - STRONG: length>=12 and meets ALL 4 categories (upper, lower, digit, special)
    - MEDIUM: length>=8 and meets at least 3 categories
    - WEAK: anything else
    """
    feedback = []

    try:
        if password is None:
            return "WEAK", ["Password is None (no input)."]

        length_ok = len(password) >= 8
        upper_ok = any(c.isupper() for c in password)
        lower_ok = any(c.islower() for c in password)
        digit_ok = any(c.isdigit() for c in password)
        special_ok = any(c in SPECIALS for c in password)

        if not length_ok:
            feedback.append("Make it at least 8 characters long.")
        if not upper_ok:
            feedback.append("Add at least one uppercase letter (A-Z).")
        if not lower_ok:
            feedback.append("Add at least one lowercase letter (a-z).")
        if not digit_ok:
            feedback.append("Add at least one number (0-9).")
        if not special_ok:
            feedback.append("Add at least one special character (e.g., !@#$%^&*).")

        categories_met = sum([upper_ok, lower_ok, digit_ok, special_ok])

        if len(password) >= 12 and categories_met == 4:
            return "STRONG", []
        elif length_ok and categories_met >= 3:
            return "MEDIUM", feedback
        else:
            return "WEAK", feedback

    except Exception as e:
        return "WEAK", [f"Error checking password: {e}"]


if __name__ == "__main__":
    test_passwords = [
        "password",        # weak (no upper, no digit, no special)
        "Password1",       # medium (no special)
        "Str0ng!Passw0rd", # strong
    ]

    print("=== Password Strength Checker Tests ===")
    for pw in test_passwords:
        rating, notes = check_password_strength(pw)
        print(f"\nPassword: {pw}")
        print(f"Rating: {rating}")
        if rating == "WEAK" and notes:
            print("Missing:")
            for n in notes:
                print(f"- {n}")
        elif notes:
            # Notes as suggestions ig
            print("Suggestions:")
            for n in notes:
                print(f"- {n}")
