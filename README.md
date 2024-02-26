
# Overview
  A password manager application built with Flask, using SQL to securely manage user credentials. It provides functionalities for users to sign up, sign in, add, update, delete, and view their credentials securely. The application uses encryption and hashing techniques to ensure the security of user data.

- ### Feature of the Password Manager
  - User Authentication: Users can sign up with a unique email and password. Passwords are securely hashed using bcrypt.
  - Secure Storage: User credentials are encrypted using Fernet symmetric encryption before storing them in the database.
  - Credential Management: Users can add, update, delete, and view their credentials. Updates to credentials are encrypted before storing.

- ### Usage
    1. Sign Up: Create a new account by providing a unique email and password.

    2. Sign In: Log in with your email and password.

    3. Add Credentials: Add new credentials by providing the website, username, password, URL, and optional notes.

    4. View Credentials: View all saved credentials in your vault.

    5. Update Credentials: Edit existing credentials, including the website, username, password, URL, and notes.

    6. Delete Credentials: Remove credentials from your vault.

    7. Log Out: Log out of your account
 
      
- ### Security Feature
    - Password Hashing: User passwords are hashed using bcrypt, ensuring that even if the database is compromised, passwords remain secure.
    - Encryption: User credentials are encrypted using Fernet symmetric encryption before storing them in the database. Decryption is only done when needed and is performed on the server-side.
    - Secure Communication: The application uses HTTPS to encrypt data transmitted between the client and the server. <br><br>
  
## Database

- ### Database Model
  - 'User': Represents user accounts and stores user information such as email, password hash, and cipher suite key.
  - 'UserCredential': Stores user credentials including website, username, encrypted password, and associated user ID.
  - 'CipherSuite': Stores encryption keys associated with users.

- ### Encryption
  -  Passwords stored in the database are encrypted using Fernet symmetric encryption before being stored.
  -  The encryption key used for each user is stored securely within the 'CipherSuite' table and associated with the user.
  -  Encryption and decryption of passwords are performed using the Fernet encryption algorithm provided by the 'cryptography' library.

- ### Data Integrity
  - Constraints are used to enforce data integrity rules within the database, ensuring that only valid and consistent data is stored.
  - Unique constraints are applied to email addresses in the User table to prevent duplicate accounts.
  - Passwords are hashed using bcrypt before being stored in the database, ensuring secure storage and authentication.


## Pictures of the Application
<img width="1498" alt="Screenshot 2024-02-25 at 12 04 44 AM" src="https://github.com/candycorn1546/PasswordManager/assets/157404986/fdfa3784-b28b-4654-a3f3-1c782a44f31f">
<br><br>
<img width="1508" alt="Screenshot 2024-02-25 at 10 39 01 PM" src="https://github.com/candycorn1546/PasswordManager/assets/157404986/1944e15e-47ae-4f8c-ab27-7e32958a426e">
<br><br>
<img width="1498" alt="Screenshot 2024-02-25 at 12 06 12 AM" src="https://github.com/candycorn1546/PasswordManager/assets/157404986/612f3e57-3605-4263-9c88-73936c197032">
<br><br>
<img width="1488" alt="Screenshot 2024-02-25 at 10 39 15 PM" src="https://github.com/candycorn1546/PasswordManager/assets/157404986/f55a6301-f1ae-42fd-9a14-0033c9219a76">
<br><br>
<img width="1493" alt="Screenshot 2024-02-25 at 10 39 37 PM" src="https://github.com/candycorn1546/PasswordManager/assets/157404986/d989dde3-ba54-4a5a-a403-e25f77600ff0">
<br><br>
<img width="1083" alt="Screenshot 2024-02-25 at 10 41 44 PM" src="https://github.com/candycorn1546/PasswordManager/assets/157404986/a06f8395-edba-4e45-84ee-d5a6f70e4073">

    An example of the user credential database, the password are encrypted and stored by the user credential unique ID






