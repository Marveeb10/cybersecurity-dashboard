from flask import Flask, render_template, request, send_file
import pandas as pd
import os
import io

app = Flask(__name__)
last_results = None  # to store last analysis for export

@app.route("/", methods=["GET", "POST"])
def index():
    global last_results
    results = None
    if request.method == "POST":
        file = request.files["file"]
        if file and file.filename.endswith(".csv"):
            filepath = os.path.join("uploads", file.filename)
            file.save(filepath)

            df = pd.read_csv(filepath)

            # Failed logins & lockouts
            failed_logins = len(df[df["EventId"] == 4625])
            account_lockouts = len(df[df["EventId"] == 4740])

            # Top offender IPs
            ip_counts = df["IP"].value_counts().head(5)
            ip_total = df["IP"].count()
            ip_data = [
                {"IP": ip, "Count": count, "Percent": f"{(count/ip_total*100):.1f}%"}
                for ip, count in ip_counts.items()
            ]

            # Top targeted accounts
            acct_counts = df["Account"].value_counts().head(5)
            acct_total = df["Account"].count()
            acct_data = [
                {"Account": acct, "Count": count, "Percent": f"{(count/acct_total*100):.1f}%"}
                for acct, count in acct_counts.items()
            ]

            # Threat level
            if failed_logins > 20 or account_lockouts > 5:
                threat = {"label": "HIGH RISK", "color": "#ff4444", "bg_class": "risk-high"}
            elif failed_logins > 10:
                threat = {"label": "MEDIUM RISK", "color": "#ffcc00", "bg_class": "risk-medium"}
            else:
                threat = {"label": "LOW RISK", "color": "#00cc66", "bg_class": "risk-low"}

            results = {
                "failed_logins": failed_logins,
                "account_lockouts": account_lockouts,
                "top_ips": ip_data,
                "top_accounts": acct_data,
                "threat": threat,
            }

            last_results = results  # save for export

    return render_template("index.html", results=results)

@app.route("/export_csv")
def export_csv():
    global last_results
    if not last_results:
        return "No analysis results to export", 400

    results = last_results
    output = io.StringIO()

    # Summary
    df_summary = pd.DataFrame({
        "Metric": ["Failed Logins", "Account Lockouts", "Threat Level"],
        "Value": [results["failed_logins"], results["account_lockouts"], results["threat"]["label"]]
    })

    # Top IPs and Accounts
    df_ips = pd.DataFrame(results["top_ips"])
    df_accts = pd.DataFrame(results["top_accounts"])

    # Write to CSV (multi-part)
    df_summary.to_csv(output, index=False)
    output.write("\n\nTop Offender IPs\n")
    df_ips.to_csv(output, index=False)
    output.write("\n\nTop Targeted Accounts\n")
    df_accts.to_csv(output, index=False)

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="analysis_report.csv"
    )

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)
