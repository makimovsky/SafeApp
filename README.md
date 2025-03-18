# SafeApp

SafeApp is a secure web application built with **Flask**, allowing users to create posts using **Markdown**. It prioritizes security and includes several protective mechanisms.

## 🔒 Security Features

- **Two-Factor Authentication (TOTP)** – Requires users to enable **Time-Based One-Time Passwords (TOTP)** for additional security.
- **Password Hashing** – All stored passwords are securely hashed to prevent unauthorized access.
- **RSA Signatures** – Notes are digitally signed using **RSA keys**, allowing verification of authenticity.
- **Password Management** – Users can securely change their passwords.
- **SSL Encryption** – Communication is encrypted with **SSL/TLS** to ensure secure data transmission.
- **Docker Deployment** – The app runs in a **Docker** container with:
  - **uWSGI** for application serving
  - **Nginx** as a reverse proxy
  - **Docker Compose** for orchestration
- **Password Strength Enforcement** – Passwords are checked for entropy-based strength, and repeated failed login attempts result in temporary IP blocking.
- **Content Validation & Sanitization** – All submitted content is sanitized to prevent security risks.

## 🚀 Running SafeApp with Docker

### 1️⃣ Create an `ssl` Directory
Inside the `nginx/` folder, create a subdirectory named `ssl/`.

### 2️⃣ Generate an SSL Certificate & Key
Place your **SSL certificate** and **private key** inside `nginx/ssl/`:

- `nginx.crt` – Your SSL certificate
- `nginx.key` – Your SSL private key

### 3️⃣ Start the Application
Run the following command to build and launch the application:

```sh
docker-compose up --build
```

Your SafeApp instance should now be up and running securely! ✅
