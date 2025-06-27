# Secure-App
Defenses for Common Threats

Secure User Management and Input Handling (Python)

This project demonstrates best practices in securely managing user data and handling common web security issues in Python, including:

- Password hashing with salt using PBKDF2-HMAC-SHA256
- Password verification resistant to timing attacks
- Username validation to prevent SQL injection
- Input sanitization to prevent Cross-Site Scripting (XSS)
- Secure database access with parameterized queries
- Basic error handling to avoid sensitive info leaks

Technologies:

- Python 3.x standard libraries: hashlib, hmac, os, re, html, sqlite3

Features:

1. Secure Password Storage
   - Random 16-byte salt generation per password
   - 100,000 iterations of PBKDF2-HMAC-SHA256
   - Storage format: salt (hex) + hash (hex)

2. Password Verification
   - Extracts salt from stored hash
   - Uses constant-time comparison

3. Input Validation and Sanitization
   - Usernames limited to alphanumeric + underscore, 3-30 chars
   - HTML escaping for user inputs to mitigate XSS

4. Secure Database Interaction
   - SQLite database 'secure_app.db'
   - Parameterized queries prevent SQL injection
   - Creates users table if not existing

5. Error Handling
   - Example safe divide function handling division by zero gracefully

Usage:

- Run the script to add a sample user with username "secure_user" and password "StrongP@ssw0rd!"
- The script will print sanitized comment example and demonstrate error handling

Requirements:

- Python 3.x
- No external dependencies required

To run:

python your_script_name.py

License:

MIT License

Author:

Christopher Kelley
