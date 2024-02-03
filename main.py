from cryptography.fernet import Fernet
import json
import getpass

class PasswordManager:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.passwords = {}

    def encrypt(self, data):
        encrypted_data = self.cipher_suite.encrypt(data.encode())
        return encrypted_data

    def decrypt(self, data):
        decrypted_data = self.cipher_suite.decrypt(data).decode()
        return decrypted_data

    def save_password(self, service, username, password):
        encrypted_username = self.encrypt(username)
        encrypted_password = self.encrypt(password)
        self.passwords[service] = {'username': encrypted_username, 'password': encrypted_password}
        self.save_to_file()

    def retrieve_password(self, service):
        if service in self.passwords:
            encrypted_username = self.passwords[service]['username']
            encrypted_password = self.passwords[service]['password']
            username = self.decrypt(encrypted_username)
            password = self.decrypt(encrypted_password)
            return username, password
        else:
            return None

    def save_to_file(self):
        with open('passwords.json', 'w') as file:
            json.dump(self.passwords, file)

    def load_from_file(self):
        try:
            with open('passwords.json', 'r') as file:
                self.passwords = json.load(file)
        except FileNotFoundError:
            pass

def main():
    manager = PasswordManager()
    manager.load_from_file()

    while True:
        print("\nPassword Manager Menu:")
        print("1. Save Password")
        print("2. Retrieve Password")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            service = input("Enter the service: ")
            username = input("Enter your username: ")
            password = getpass.getpass("Enter your password: ")
            manager.save_password(service, username, password)
            print("Password saved successfully!")

        elif choice == '2':
            service = input("Enter the service to retrieve password: ")
            credentials = manager.retrieve_password(service)
            if credentials:
                print(f"Username: {credentials[0]}")
                print(f"Password: {credentials[1]}")
            else:
                print(f"No password found for {service}")

        elif choice == '3':
            manager.save_to_file()
            print("Password Manager closed.")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
