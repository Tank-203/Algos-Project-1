##FUNCTION CALL: GENERATE RSA KEYS
print("RSA keys have been generated successfully!")

while True:
    try:
        print("Please select your user type:\n\t1. Public user\n\t2. Owner\n\t3. Quit")
        print(">> ", end="")
        user_type = int(input())
        if user_type in [1, 2, 3]:
            break
        else:
            print("Invalid selection. Please enter a number between 1 and 3.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")
##END OF FIRST SECTION

if user_type == 1:
    while True:
        try:
            print("What would you like to do?\n\t1. Send an encrypted message\n\t2. Authenticate a digital signature\n\t3. Back")
            print(">> ", end="")
            user_choice = int(input())
            if user_choice in [1, 2, 3]:
                break
            else:
                print("Invalid selection. Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")
elif user_type == 2:
    while True:
        try:
            print("What would you like to do?")
            print("\t1. Decrypt a received a message\n\t2. Digitally sign a message\n\t3. Show the keys\n\t"
                  "4. Generate new keys\n\t5. Back")
            print(">> ", end="")
            user_choice = int(input())
            if user_choice in [1, 2, 3]:
                break
            else:
                print("Invalid selection. Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")
