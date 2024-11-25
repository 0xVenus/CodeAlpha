# Network-Based Intrusion Detection System (NIDS)

Develop a network-based intrusion detection system using tools like **Snort** or **Suricata**. This includes setting up rules, generating alerts, and visualizing attacks using the ELK Stack.

---

## Step 1: Install and Set Up the NIDS Tool

### Using Snort:
1. **Install Snort**:
   ```
   sudo apt-get update
   sudo apt-get install snort


# Locate Snort’s configuration file (usually /etc/snort/snort.conf).
Update the HOME_NET variable to specify your network range:
```
var HOME_NET 192.168.1.0/24
Add custom rules to /etc/snort/rules/local.rules.
Using Suricata:
sudo apt-get install suricata
```
# Configure Suricata:

Update the configuration file (/etc/suricata/suricata.yaml):
yaml
HOME_NET: "[192.168.1.0/24]"
Add rules to the rules directory (e.g., custom.rules).

**Create Custom Rules**
Rule: Detect a Ping Sweep

For Snort:
```
alert icmp any any -> any any (msg:"Ping Sweep Detected"; sid:1000001; rev:1;)
For Suricata:


alert icmp any any -> any any (msg:"Ping Sweep Detected"; sid:1000001; rev:1;)
Rule: Detect a Port Scan
For Snort:


alert tcp any any -> any any (flags:S; msg:"Port Scan Detected"; sid:1000002; rev:1;)
For Suricata:

alert tcp any any -> any any (flags:S; msg:"Port Scan Detected"; sid:1000002; rev:1;)
Add these rules to the respective local.rules or custom.rules file, then reload or restart the NIDS tool:
```

```
sudo systemctl restart snort
sudo systemctl restart suricata
```
# Testing the Rules
I used Nmap to simulate attacks and check if alerts are generated.

Simulate a Ping Sweep:

```
nmap -sn 192.168.1.0/24
Simulate a Port Scan:
nmap -sS 192.168.1.100
Check logs:
```

Snort logs are typically found in /var/log/snort/.
Suricata logs are in /var/log/suricata/.
# Visualize the Alerts
Use the ELK Stack (Elasticsearch, Logstash, and Kibana) for visualization.

# Install ELK Stack
Install Elasticsearch, Logstash, and Kibana using their official repositories:

```sudo apt-get install elasticsearch logstash kibana```

# Configure Logstash
Create a Logstash pipeline to parse Snort/Suricata logs. Example configuration (/etc/logstash/conf.d/nids.conf):

```
input {
    file {
        path => "/var/log/suricata/eve.json"  # Suricata log file
        start_position => "beginning"
        codec => "json"
    }
}

filter {
    if [event_type] == "alert" {
        mutate {
            add_field => { "alert_type" => "%{[alert][category]}" }
        }
    }
}

output {
    elasticsearch {
        hosts => ["localhost:9200"]
        index => "nids-alerts"
    }
}
```

Restart Logstash:
```
sudo systemctl restart logstash
```

# Visualize in Kibana
Launch Kibana:

```sudo systemctl start kibana```

Access it in a browser: http://localhost:5601.
Create a new dashboard to display:
Line Chart: Alerts over time.
Pie Chart: Alert categories (e.g., Port Scan, Ping Sweep).
Data Table: Source and destination IPs.
# Automate and Monitor
Send Alerts: I used Python to monitor logs and send real-time alerts via email or Slack.

**script to parse logs:**

```
python
Copy code
import json
import smtplib

def send_email(alert):
    server = smtplib.SMTP('smtp.example.com', 587)
    server.starttls()
    server.login("your_email@example.com", "password")
    message = f"Subject: NIDS Alert\n\n{alert}"
    server.sendmail("your_email@example.com", "recipient@example.com", message)
    server.quit()

def monitor_logs(log_file):
    with open(log_file, 'r') as f:
        for line in f:
            log = json.loads(line)
            if "alert" in log:
                alert = f"Alert: {log['alert']['signature']} from {log['src_ip']} to {log['dest_ip']}"
                print(alert)
                send_email(alert)

monitor_logs("/var/log/suricata/eve.json")
```

Set Up Dashboards: Continuously monitor attack trends and respond accordingly.

Final Output
Real-Time Alerts: Automated notifications for detected attacks.
Dashboards: Kibana visualizations showing attack patterns and source/destination data.
Custom Rules: Snort/Suricata rules to detect various attack types.
This project provides a comprehensive network intrusion detection system with detailed visualization and alerting capabilities.
