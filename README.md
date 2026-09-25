# 🛡️ AI Cybersecurity Threat Detection System

A complete educational final-year CSE/IT project demonstrating network-flow collection, threat classification, alerts, reporting, authentication, and an admin dashboard.

## Features
- User and Admin login
- Network traffic input
- Threat classification
- Attack types: Normal, Suspicious Activity, Port Scan, DDoS
- Severity and confidence
- Alert generation
- Security dashboard
- Threat reports
- Admin dashboard
- SQLite database (zero configuration)
- MySQL schema starter
- Sample network-flow CSV
- Responsive frontend

## Demo Login
Admin: `admin` / `admin123`
User: `student` / `student123`

## Run on Windows
1. Install Python 3.10+.
2. Open Command Prompt in this project folder.
3. Run:
   `python -m venv venv`
4. Activate:
   `venv\Scripts\activate`
5. Install:
   `pip install -r requirements.txt`
6. Start:
   `python app.py`
7. Open:
   `http://127.0.0.1:5000`

## Run on Linux/macOS
`python3 -m venv venv`
`source venv/bin/activate`
`pip install -r requirements.txt`
`python app.py`

## Database
The demo uses SQLite and automatically creates `cybersecurity.db` on first run. `schema.sql` contains the core users schema and the application creates all required tables.

For a final-year extension, migrate the same tables to MySQL and add a real packet/network-flow ingestion service.

## About the "AI"
The included `ml_model.py` uses transparent feature-based classification so the project runs without downloading a model. For an academic ML version, train a scikit-learn classifier using a lawful cybersecurity dataset such as CIC-IDS2017 or UNSW-NB15, save the model, and replace `classify_traffic()`.

## Project Structure
- `app.py` — Flask routes, authentication, database operations
- `ml_model.py` — detection/classification logic
- `templates/` — frontend pages
- `static/style.css` — responsive UI
- `data/sample_network_logs.csv` — sample data
- `schema.sql` — database starter
- `requirements.txt` — Python dependencies

## Safety
This project is intended for defensive education and testing with authorized data only. Do not use it to monitor networks or systems without permission.
