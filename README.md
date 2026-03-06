# Ideal Spoon with MongoDB

A Flask web application demonstrating the transition from a **single-file handler architecture** to a **modular and scalable Flask project structure** using **MongoDB with MongoEngine**.

## Overview

This project was originally implemented as a **small Flask application with all logic inside a single handler file**. As the project grew, it was refactored into a **structured architecture using the Application Factory pattern and Flask Blueprints** to improve maintainability, scalability, and code organization.

The application includes basic **authentication features** and a **blog system**, while integrating **MongoDB** for data storage.

## Features

* Modular Flask architecture
* Application Factory pattern
* Blueprint-based routing
* MongoDB integration using MongoEngine
* User authentication (Login, Register, Forgot Password)
* Blog post management
* Jinja2 templating
* Organized static assets (CSS, JS, images)

## Project Structure

```
ideal-spoon-with-mongodb/
│
├── app/                        # Main application package
│   ├── __init__.py             # Application Factory (create_app)
│   ├── models.py               # MongoEngine schemas (User, BlogPost)
│   │
│   ├── routes/                 # Blueprints
│   │   ├── auth/
│   │   │   ├── routes.py       # Login, Register, Forget Password
│   │   │   └── forms.py        # WTForms for authentication
│   │   │
│   │   └── main/
│   │       └── routes.py       # Home, Blog posts, error handlers
│   │
│   ├── static/                 # CSS, JavaScript, Images
│   ├── templates/              # Jinja2 HTML templates
│   └── utils/                  # Helper utilities (Gravatar, decorators)
│
├── config.py                   # Application configuration (MongoDB URI)
├── run.py                      # Entry point to start the Flask server
├── requirements.txt            # Project dependencies
└── .gitignore                  # Ignored files (venv, cache, etc.)
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/ideal-spoon-with-mongodb.git
cd ideal-spoon-with-mongodb
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

**Windows**

```
venv\Scripts\activate
```

**Linux / Mac**

```
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure MongoDB

Update the MongoDB connection string inside:

```
config.py
```

Example:

```
MONGODB_SETTINGS = {
    "host": "mongodb://localhost:27017/blogdb"
}
```

### 5. Run the application

```bash
python run.py
```

The application will start on:

```
http://127.0.0.1:5000
```

## Technologies Used

* Python
* Flask
* MongoDB
* MongoEngine
* WTForms
* Jinja2
* HTML / CSS / JavaScript

## Purpose of the Project

The goal of this project is to demonstrate **how to refactor a simple Flask application into a clean, production-style architecture** by separating configuration, models, routes, templates, and utilities.

This structure makes the project easier to maintain and extend with additional features such as APIs, user roles, or larger database models.

## License

This project is open source and available under the MIT License.
