THREAT_DATABASE = {
    "HIGH": ["rm -rf", "DROP TABLE", "AWS_SECRET_ACCESS_KEY"],
    "MEDIUM": ["sudo", "chmod 777", "eval("],
    "LOW": ["password", "token", "secret"]
}

def inspect_input_advanced(user_input: str) -> dict:
    """
    Analyzes against a categorized threat database.
    Returns a dictionary report.
    """

    clean_input = user_input.lower()

    # Check HIGH risk
    for keyword in THREAT_DATABASE["HIGH"]:
        if keyword.lower() in clean_input:
            return {
                "status": "BLOCKED",
                "risk_level": "HIGH",
                "risk_score": 95,
                "flagged_term": keyword,
                "reason": f"Critical secutiry hazard: '{keyword}' detected."
            }

    # Check MEDIUM risk
    for keyword in THREAT_DATABASE["MEDIUM"]:
        if keyword.lower() in clean_input:
            return {
                "status": "WARNING",
                "risk_level": "MEDIUM",
                "risk_score": 50,
                "flagged_term": keyword,
                "reason": f"Elevated privilege command: '{keyword}' detected."
            }

        return{
            "status": "PASSED",
            "risk_level": "LOW",
            "risk_score": 0,
            "flagged_term": None,
            "reason": "Input passed all security checks."
        }
        

if __name__ == "__main__":

    sample_input = "Please run sudo systemctl restart nginx"
    result = inspect_input_advanced(sample_input)

    print("__REPORT__")
    print(f"Status: {result['status']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Details: {result['reason']}")
