import os
import pandas as pd
from flask import Flask, render_template, request, send_file

app = Flask(__name__)

# === Ensure uploads folder exists ===
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# === Threat level helper ===
def get_threat_level(failed_logins, account_lockouts):
    if failed_logins == 0 and account_lockouts == 0:
        return {"label": "LOW RISK", "color": "#00ffcc"}
    elif failed_logins < 5 and account_lockouts < 2:
        return {"label": "MEDIUM RISK", "color": "#ffcc00"}
    else:
        return {"label": "HIGH RISK", "color": "#ff4444"}


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    if request.method == "POST":
        file = request.files["file"]
        if file and file.filename.endswith(".csv"):
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            df = pd.read_csv(filepath)

            # === Basic analysis ===
            failed_logins = len(df[df["EventId"] == 4625])
            account_lockouts = len(df[df["EventId"] == 4740])

            # Top 5 offender IPs
            ip_counts = df["IP"].value_counts().head(5)
            ip_total = df["IP"].count() if not df["IP"].empty else 1
            ip_data = [
                {"IP": ip, "Count": count, "Percent": f"{(count / ip_total * 100):.1f}%"}
                for ip, count in ip_counts.items()
            ]

            # Top 5 targeted accounts
            acct_counts = df["Account"].value_counts().head(5)
            acct_total = df["Account"].count() if not df["Account"].empty else 1
            acct_data = [
                {"Account": acct, "Count": count, "Percent": f"{(count / acct_total * 100):.1f}%"}
                for acct, count in acct_counts.items()
            ]

            results = {
                "failed_logins": failed_logins,
                "account_lockouts": account_lockouts,
                "top_ips": ip_data,
                "top_accounts": acct_data,
                "threat": get_threat_level(failed_logins, account_lockouts),
            }

            # Save CSV summary
            export_path = os.path.join(UPLOAD_FOLDER, "log_analysis_report.csv")
            summary_df = pd.DataFrame({
                "Failed Logins": [failed_logins],
                "Account Lockouts": [account_lockouts],
                "Threat Level": [results["threat"]["label"]],
            })
            summary_df.to_csv(export_path, index=False)

    return render_template("index.html", results=results)


@app.route("/export_csv")
def export_csv():
    filepath = os.path.join(UPLOAD_FOLDER, "log_analysis_report.csv")
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return "No report available yet. Upload a log file first."


if __name__ == "__main__":
    app.run(debug=True)
