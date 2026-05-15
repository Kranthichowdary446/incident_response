from flask import Flask, render_template, jsonify, send_file
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from sklearn.ensemble import RandomForestClassifier
import io, random, datetime, hashlib, time

app = Flask(__name__)
incidents = []
playbook_logs = []

threat_types = ["Phishing Email", "Brute Force Attack", "Malware Detected", "Unauthorized Access", "DDoS Attempt"]

mitre_mapping = {
    "Phishing Email":      {"id": "T1566", "tactic": "Initial Access"},
    "Brute Force Attack":  {"id": "T1110", "tactic": "Credential Access"},
    "Malware Detected":    {"id": "T1204", "tactic": "Execution"},
    "Unauthorized Access": {"id": "T1078", "tactic": "Defense Evasion"},
    "DDoS Attempt":        {"id": "T1498", "tactic": "Impact"}
}

iot_devices = [
    "Smart Camera", "IoT Sensor", "Smart Router",
    "Industrial Controller", "Smart Thermostat"
]

X_train = [[0,14,201],[0,23,45],[0,2,178],[1,3,62],[1,4,176],[1,22,112],[2,1,120],[2,13,88],[2,3,200],[3,9,159],[3,17,88],[3,11,45],[4,2,100],[4,15,200],[4,8,150]]
y_train = [94,91,88,67,65,70,96,93,97,31,35,28,89,85,92]
ai_model = RandomForestClassifier(n_estimators=10, random_state=42)
ai_model.fit(X_train, y_train)

def get_ai_score(threat_type, ip):
    threat_idx = threat_types.index(threat_type) if threat_type in threat_types else 0
    hour = datetime.datetime.now().hour
    ip_last = int(ip.split('.')[-1])
    return int(ai_model.predict([[threat_idx, hour, ip_last]])[0])

def run_playbook(incident):
    if incident['severity'] == 'High':
        steps = [
            f"[STEP 1] Threat detected: {incident['type']} from {incident['ip']}",
            f"[STEP 2] MITRE ATT&CK Technique: {incident['mitre_id']} - {incident['mitre_tactic']}",
            f"[STEP 3] AI scoring complete - Danger Score: {incident['ai_score']}%",
            f"[STEP 4] Playbook triggered: Auto-Containment Protocol",
            f"[STEP 5] Source IP {incident['ip']} blocked at firewall",
            f"[STEP 6] Endpoint quarantined successfully",
            f"[STEP 7] User credentials reset",
            f"[STEP 8] SOC team alerted via dashboard",
            f"[STEP 9] Incident report generated - ID: {incident['id']}",
            f"[STEP 10] NIST IR framework compliance verified"
        ]
    else:
        steps = [
            f"[STEP 1] Threat detected: {incident['type']} from {incident['ip']}",
            f"[STEP 2] MITRE ATT&CK Technique: {incident['mitre_id']} - {incident['mitre_tactic']}",
            f"[STEP 3] AI scoring complete - Danger Score: {incident['ai_score']}%",
            f"[STEP 4] Flagged for manual review",
            f"[STEP 5] SOC analyst notified",
            f"[STEP 6] Monitoring mode activated for {incident['ip']}"
        ]
    playbook_logs.append({"incident_id": incident['id'], "time": incident['time'], "steps": steps})

def generate_incident():
    threats = [
        {"type": "Phishing Email", "severity": "High", "ip": "192.168.1."+str(random.randint(1,255))},
        {"type": "Brute Force Attack", "severity": "Medium", "ip": "10.0.0."+str(random.randint(1,255))},
        {"type": "Malware Detected", "severity": "High", "ip": "172.16.0."+str(random.randint(1,255))},
        {"type": "Unauthorized Access", "severity": "Low", "ip": "192.168.0."+str(random.randint(1,255))},
        {"type": "DDoS Attempt", "severity": "High", "ip": "10.10.0."+str(random.randint(1,255))}
    ]
    threat = random.choice(threats)
    ai_score = get_ai_score(threat["type"], threat["ip"])
    mitre = mitre_mapping.get(threat["type"], {"id": "T0000", "tactic": "Unknown"})
    iot_device = random.choice(iot_devices) if random.random() > 0.5 else None
    incident = {
        "id": hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:8].upper(),
        "type": threat["type"],
        "severity": threat["severity"],
        "ip": threat["ip"],
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Contained" if threat["severity"] == "High" else "Monitoring",
        "action": "Blocked & Quarantined" if threat["severity"] == "High" else "Flagged for Review",
        "ai_score": ai_score,
        "mitre_id": mitre["id"],
        "mitre_tactic": mitre["tactic"],
        "iot_device": iot_device
    }
    incidents.append(incident)
    run_playbook(incident)
    return incident

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/incidents')
def get_incidents():
    return jsonify(incidents[-20:])

@app.route('/api/simulate')
def simulate():
    time.sleep(4)
    return jsonify(generate_incident())

@app.route('/api/simulate_high')
def simulate_high():
    time.sleep(4)
    ip = "192.168.1."+str(random.randint(1,255))
    ai_score = get_ai_score("Phishing Email", ip)
    incident = {
        "id": hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:8].upper(),
        "type": "Phishing Email",
        "severity": "High",
        "ip": ip,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Contained",
        "action": "Blocked & Quarantined",
        "ai_score": ai_score,
        "mitre_id": "T1566",
        "mitre_tactic": "Initial Access",
        "iot_device": random.choice(iot_devices)
    }
    incidents.append(incident)
    run_playbook(incident)
    return jsonify(incident)

@app.route('/api/stats')
def stats():
    total = len(incidents)
    high = len([i for i in incidents if i['severity'] == 'High'])
    contained = len([i for i in incidents if i['status'] == 'Contained'])
    return jsonify({"total": total, "high_severity": high, "contained": contained, "mttd": "< 1 min", "mttr": "< 5 mins"})

@app.route('/api/playbook_logs')
def get_playbook_logs():
    return jsonify(playbook_logs[-5:])

@app.route('/api/report')
def generate_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("INCIDENT RESPONSE REPORT", styles['Title']))
    elements.append(Paragraph("AI-Powered SOAR Platform | Confidential", styles['Normal']))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"Total Incidents: {len(incidents)}", styles['Normal']))
    elements.append(Spacer(1, 20))
    data = [["ID", "Type", "Severity", "IP", "Time", "Status", "Action", "AI Score", "MITRE", "IoT Device"]]
    for inc in incidents:
        data.append([
            inc['id'], inc['type'], inc['severity'],
            inc['ip'], inc['time'], inc['status'],
            inc['action'], f"{inc.get('ai_score', 0)}%",
            inc.get('mitre_id', 'N/A'),
            inc.get('iot_device', 'N/A') or 'N/A'
        ])
    table = Table(data, colWidths=[45,80,45,75,90,55,95,40,40,70])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,0), 8),
        ('FONTSIZE', (0,1), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey])
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='incident_report.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
