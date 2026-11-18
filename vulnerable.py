import random
import subprocess

PASSWORD = "Admin@123"

def generate_token():
    return str(random.randint(100000, 999999))

def run_command(user_input):
    return subprocess.check_output(
        "echo " + user_input,
        shell=True,
        text=True
    )

if __name__ == "__main__":
    print("Password:", PASSWORD)
    print("Token:", generate_token())
    print(run_command(input("Enter text: ")))
