import re
import getpass
def analyse(password):
    score = 0
    suggestion=[]
    if len(password) < 8:
        score += 1
        suggestion.append("Password is too short. Consider using at least 8 characters.")
    if not re.search(r"[a-z]", password):
        score += 1
        suggestion.append("Password should contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        score += 1
        suggestion.append("Password should contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        score += 1
        suggestion.append("Password should contain at least one digit.")
    if not re.search(r"[!@#$%^&*()-+]", password):
        score += 1
        suggestion.append("Password should contain at least one special character.")
    
    if score<=2: 
        print("Password is weak. Suggestions for improvement:")
        for s in suggestion:
            print(f"- {s}")           
    elif score<=4:
        print("Password is moderate. Suggestions for improvement:")
        for s in suggestion:
            print(f"- {s}")
    else:
        print("Password is strong.")
    print(f"Password strength score: {score}/6")
    if suggestion:
        print("Suggestions for improvement:")
        for s in suggestion:
            print(f"- {s}")
    else:
        print("No suggestions. Your password is strong.")
    print("Password strength analyzer:")
    print=getpass.getpass("Enter your password for analysis: ")
    analyze(password)
    return score, suggestion