
#Overview
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






