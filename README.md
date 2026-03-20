# Blog website powered with python(flask) and MongoDB

A Flask web application demonstrating the transition from a **single-file handler architecture** to a **modular and scalable Flask project structure** using **MongoDB with MongoEngine**.

## Preview
check the preview of my site on this link. It takes few seconds to load since its a free tier of hosting and spin down after 50 seconds of inactivity
https://blog-of-gg.onrender.com

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
git clone https://github.com/GG-Ranjeet/Blogging-Website-Between-Semester.git
cd Blogging-Website-Between-Semester
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

**Windows**
for cmd
```
.venv\Scripts\activate
```
for powershell
```
.venv\Scripts\Activate.ps1
```

**Linux / Mac**

```
source .venv/bin/activate
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
or use the .env file with required uri I used in this config

Example:

```
MONGODB_SETTINGS = {
    "host": "mongodb://localhost:27017/blogdb"
}
```

```.env
MONGO_URI='your_mongo_uri'
FLASK_KEY='THIS_IS_MY_TEST_TOKEN'
DEBUGING='True'
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



