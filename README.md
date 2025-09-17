# Cybersecurity Dashboard

This project is a practical simulation of a Security Information and Event Management (SIEM) tool.
It enables users to upload Windows Security Event Logs (CSV format) and instantly analyze failed login attempts, account lockouts, and targeted accounts.
The dashboard presents results through clear tables, interactive charts, and a risk level indicator to help identify brute-force activity or compromised accounts.

## Features

- **Failed Login Detection**
Detects failed login attempts (Event ID 4625) and reports total suspicious activity.

- **Account Lockout Detection**
Tracks account lockouts (Event ID 4740) to highlight repeated attacks.

- **Interactive Web Dashboard**
Built with Flask and Chart.js, providing real-time analysis and visualization.

- **Data Visualizations**

Bar chart showing top offender IP addresses

Pie chart showing the most targeted accounts

- **Threat Level Indicator**
Dynamically adjusts between Low, Medium, and High risk based on log activity.

- **Summary Tables**
Displays detailed statistics on suspicious IPs and accounts for further investigation.

## Project Structure
cybersecurity-dashboard/
app.py               # Main Flask application

requirements.txt     # Python dependencies

Procfile             # For deployment (Heroku/Render)

runtime.txt          # Python runtime version

.gitignore           # Ignore venv, pycache, uploads
│
sample_events.csv    # Demo dataset

templates/index.html       # Frontend dashboard

## Technologies Used

- **Python (Flask, pandas)** – Backend and log parsing

- **Chart.js** – Interactive data visualization

- **HTML/CSS/Bootstrap** – Frontend design and layout

- **GitHub, Heroku/Render** – Version control and deployment

## Demo Mode

A sample dataset (sample_events.csv) is included so the dashboard can be tested without real log files.

## Setup Instructions

Clone the repository:

git clone https://github.com/Marveeb10/cybersecurity-dashboard.git
cd cybersecurity-dashboard

Create and activate a virtual environment:

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Run the app locally:

python app.py

Open in your browser

## Deployment

The project is ready for deployment on platforms such as Heroku or Render.
With the included Procfile and runtime.txt, it can be hosted as a live, shareable web application.

## Why This Project

This project was built to demonstrate the ability to:

Apply real-world cybersecurity monitoring concepts

Combine backend development, frontend design, and data visualization

Build and deploy a tool that mirrors the functionality of professional SIEM platforms

Deliver clear, actionable insights from raw log data
