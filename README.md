# 🛡️ SecureLog Monitor 🔎  
*A lightweight SOC-based log analysis and intrusion detection system built with Python*

---

## 🚀 Overview  

**SecureLog Monitor** is a beginner-friendly, open-source Mini-SOC log analyzer designed for students and aspiring cybersecurity professionals.  

It collects and analyzes system/network logs, converts them into structured data, applies detection rules, and generates security alerts for:

- 🚨 Brute-force login attempts  
- 🚨 Successful login after multiple failures  
- ⚠️ Suspicious traffic / repeated denied connections  

This project simulates how a **Security Operations Center (SOC)** monitors and detects cyber threats in real time.

---

## ✨ Features  

- Parses raw log files into structured **JSON and CSV**  
- Detects **brute-force login attempts**  
- Detects **successful logins after multiple failures**  
- Identifies **suspicious IP activity / denied traffic**  
- Generates alerts and stores them in a log file  
- Simple CLI-based execution  
- Beginner-friendly and easy to extend  

---

## 📂 File Structure  

```
│── analyzer.py              # Main log analyzer script  
│── network_logs.txt         # Sample log file for testing  
│── security_alerts.log      # Generated alerts file  
│── parsed_logs.json         # Structured logs (JSON)  
│── parsed_logs.csv          # Structured logs (CSV)  
│── README.md                # Project documentation  
```

---

## 🛠️ Usage  

### 1️⃣ Clone the repository  

```bash
git clone https://github.com/yourusername/securelog-monitor.git
cd securelog-monitor
```

### 2️⃣ Run the analyzer  

```bash
python analyzer.py
```

### 3️⃣ View results  

- 📄 `security_alerts.log` → Security alerts with timestamps  
- 📄 `parsed_logs.json` → Structured logs (JSON format)  
- 📄 `parsed_logs.csv` → Structured logs (CSV format)  

---

## 🧠 How It Works  

```
System Logs → Parsing → Detection Rules → Alert Generation → Output Files
```

The system continuously reads logs and applies predefined rules like:

- Multiple failed logins → Possible brute-force attack  
- Repeated denied traffic → Possible scanning activity  

---

## 🎯 Why This Project?  

This project was built to:

- Strengthen Python skills (regex, file handling, data processing)  
- Understand how SOC teams analyze logs  
- Simulate real-world intrusion detection workflows  
- Showcase practical cybersecurity skills for internships and projects  

---

## 🔮 Future Improvements  

- Add real-time monitoring (live log streaming)  
- Integrate with SIEM tools  
- Add dashboard (web UI)  
- Support firewall & IDS logs  
- Email/SMS alert system  

---

## 📖 Learning Concepts Covered  

- Log Analysis  
- Intrusion Detection Systems (IDS)  
- Regular Expressions (Regex)  
- Python Automation  
- SOC Workflow  

---

## 🧑‍💻 Author  

**Ashok Kumar**  

🎓 Cybersecurity Student  
🛡️ Aspiring SOC Analyst / Security Engineer  

---

## 📜 License  

This project is open-source and available under the **MIT License**.  
Feel free to use, modify, and contribute 🚀  
