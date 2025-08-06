# Secure Password Wallet

A secure desktop password manager with biometric authentication and OTP support.

## Features

- Biometric authentication (Touch ID/Windows Hello)
- Two-factor authentication (2FA/OTP) support
- Encrypted password storage using SQLite and bcrypt
- Modern, Apple-inspired user interface
- Dark mode support
- Password generation
- Import/Export functionality
- Categories and favorites
- Search functionality
- Secure notes

## Installation

1. Clone the repository
2. Install dependencies:
```bash
npm install
```

3. Run the application:
```bash
npm start
```

## Build

To create a distributable version:

```bash
npm run build
```

This will create platform-specific installers in the `dist` folder.

## Security Features

- Biometric authentication
- Master password protection
- Encrypted storage using bcrypt
- Secure password generation
- OTP/2FA support
- Auto-lock functionality

## Development

This application is built using:
- Electron
- SQLite3 for secure storage
- bcrypt for password hashing
- otplib for OTP functionality

## License

MIT
