# Flask Contact Management App

A complete web application for managing contacts built with Flask, featuring dual database support (MongoDB and SQLite).

## Features

- **User Authentication**: Registration, login, and password reset system
- **Contact Management**: Add and search contacts by registration number
- **Dual Database Support**: Works with both MongoDB and SQLite
- **Real-time Communication**: HTML5 WebSocket implementation
- **Responsive Design**: Bootstrap-based user interface

## Assignment Requirements Implementation

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Flask Web Application | Complete | Full Flask app with routes, templates, and forms |
| MongoDB Database | Configurable | Dual database support with MongoDB-ready architecture |
| User Login with Forgot Password | Complete | Secure authentication with email reset tokens |
| Contact Form | Complete | Mobile, email, address, and registration number |
| Contact Search | Complete | Search by registration number |
| HTML5 WebSocket | Complete | Real-time messaging and contact search |

## Database Architecture

### MongoDB Implementation Ready
The application includes complete MongoDB support. When `USE_MONGODB = True` in `app_dual.py`, it uses:

```python
# MongoDB Collections Structure
users = {
    "_id": ObjectId,
    "username": "string",
    "email": "string", 
    "password": "hashed_string",
    "created_at": "datetime"
}

contacts = {
    "_id": ObjectId,
    "user_id": "string",
    "mobile": "string",
    "email": "string",
    "address": "string", 
    "registration_number": "string",
    "created_at": "datetime"
}
