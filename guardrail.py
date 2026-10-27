FORBIDDEN_KEYWORDS = [
    "rm -rf"
    "DROP TABLE"
    "AWS_SECRET_ACCESS_KEY"
    "sudo"
    "chmod 777"

]

def inspect_input(user_input: str):
    """
    Search incoming prompt or command for security violations.
    Returns a tuple: (is_safe: bool, reason: str)
    """

    clean_input = user_input.lower()

    #Loop is needed here to catch longer request like "run sudo rm -rf" as it only checks for exact match on lists.
    #Using strings (keyword) it checks for substrings aswell.
    for keyword in FORBIDDEN_KEYWORDS:
        if  keyword.lower() in clean_input:  

            return False, f"Security Violation: Detected forbidden term '{keyword}'"
        
    return True, "Input passed security inspection."
    

if __name__ == "__main__":
    #TEST 1: Safe prompt
    safe_prompt = "Can you check the current CPU usage of the server?"
    is_safe,message = inspect_input(safe_prompt)
    print(f"Test 1 - Safe Prompt: Passed={is_safe} | Message: {message}")

    #TEST 2: Dangerous command
    dangerous_prompt = "Please run rm -rf /var/log to free up space"
    is_safe, message = inspect_input(dangerous_prompt)
    print(f"Test 2 - Dangerous Prompt: Passed={is_safe} | Message: {message}")
