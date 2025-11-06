🛡️ Nexora RiskVault – Risk Management Dashboard

A Low-Cost Security Monitoring System (SOC Approach)
Developed as part of Nexora’s Cyber Risk Management Initiative
© 2025 Nexora Technologies | Confidential Use Only

📘 Overview

Nexora RiskVault is a lightweight, Streamlit-based Risk Management Dashboard designed to automate the detection, classification, and evaluation of cybersecurity risks from log data.
It integrates AMDEC (FMEA), QQOQCCP, and PESTLEO methodologies to help identify, prioritize, and mitigate technical and organizational risks in a Security Operations Center (SOC) context.

⚙️ Key Features
🔍 Automated Risk Detection

Detects brute-force attacks, port scans, and suspicious IP activities

Dynamically computes Severity (S), Probability (P), Detectability (D), and RPN

Auto-classifies risk levels: 🔴 Critical | 🟡 Moderate | 🟢 Low

📊 AMDEC (FMEA) Matrix

Real-time generation of AMDEC Matrix directly from log data

Exports detailed Excel reports with RPN calculations

Includes Criticality Matrix (Severity × Probability) heatmap

🧠 Multi-Matrix Integration (Optional Extensions)

QQOQCCP Analysis for process-oriented risk tracking

PESTLEO Matrix for macro-environmental analysis

Preventive & Curative Actions Table with visual progress indicators

📈 Visualizations

Risk distribution charts (bar & donut)

Real-time RPN monitoring dashboard

AMDEC summary with suggested corrective actions

📤 Export & Reporting

Download processed data in CSV or Excel (multi-sheet) format

Professional templates for integration into formal reports

🚀 How to Use
🧩 Step 1: Upload or Use Demo Logs

Upload a .csv file containing basic event logs.
Example structure:

timestamp,event_type,source_ip,destination_ip,src_port,dst_port,username,message
2025-11-01 09:01:00,failed_login,10.0.0.10,192.168.1.10,55512,22,alice,Invalid password


Or enable “Use Demo Data” from the sidebar to test the app.

🧮 Step 2: Adjust Parameters

Use the sidebar controls to:

Set default detectability level

Adjust the Critical RPN Threshold

Configure brute-force and scan detection windows

📊 Step 3: Analyze & Export

View AMDEC summary and risk matrices

Download Excel report for official documentation

Review detected attack patterns and risk classifications

🧰 Tech Stack
Component	Description
Frontend/UI	Streamlit
Data Handling	Pandas, NumPy
Visualization	Plotly
Export	XlsxWriter
Version Control	GitHub
🧱 Project Structure
nexora-riskvault/
├── app.py               # Streamlit main application
├── requirements.txt     # Dependencies for Streamlit Cloud
├── sample_logs.csv      # Demo log dataset
└── README.md            # Project summary and usage guide

💡 Risk Interpretation
Risk Level	Meaning	Recommended Action
🔴 Critical	RPN > 200	Immediate mitigation & alert escalation
🟡 Moderate	100 ≤ RPN ≤ 200	Monitor & apply preventive measures
🟢 Low	RPN < 100	Routine monitoring
🌐 Deployment

Deployed on Streamlit Cloud
🔗 Live Dashboard: https://adnan7860-ai-nexora-riskvault.streamlit.app

👨‍💼 Developed By

Risk Management Department – Nexora Technologies
Project: Low-Cost Security Monitoring Dashboard (SOC Approach)
Prepared By: Adnan [Your Last Name] | Supervised By: Esaip Engineering School, France

🧩 Future Enhancements

✅ Integration of PESTLEO and QQOQCCP matrices

✅ Correlation of multiple log sources (SIEM-style)

✅ Automated alerting and email notifications

✅ Integration with cloud-based dashboards (Power BI / Grafana)

🧠 References

AMDEC (FMEA) ISO 31010 Risk Assessment Methodology

ENISA: Cyber Risk Management Frameworks

Nexora Technologies Internal SOC Guidelines
