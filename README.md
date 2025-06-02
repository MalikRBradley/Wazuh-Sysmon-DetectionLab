🛡️ Sysmon + Wazuh Detection Lab (Windows 11)
This project simulates real-time endpoint detection using Sysmon and Wazuh on a Windows 11 VM. The goal was to monitor attacker-like behavior such as ping and whoami, and verify that these events were captured, parsed, and enriched by Wazuh using the MITRE ATT&CK framework.

🧠 What I Configured
✅ Installed Sysmon64
Used the following command with a tested XML config file:
Sysmon64.exe -accepteula -i sysmonconfig.xml

✅ Edited the Wazuh agent config (ossec.conf) to include:

<localfile> <log_format>eventchannel</log_format> <location>Microsoft-Windows-Sysmon/Operational</location> </localfile>
Restarted the Wazuh agent to begin collecting Sysmon logs.

🧪 Simulated Recon Behavior
Ran the following commands in PowerShell:
ping 8.8.8.8
whoami

These actions simulate basic network and identity discovery by an attacker:

ping → T1018 – Remote System Discovery

whoami → T1033 – System Owner/User Discovery

🔍 Wazuh Detection & Visibility
Wazuh successfully captured the following details from Sysmon logs:

Command-line arguments

Parent process (PowerShell)

Username and session info

SHA1 and MD5 hashes of the executed binaries

Mapped behavior to MITRE ATT&CK rules

Event IDs: 1 (Process Creation), and more depending on the action

All of this was logged and visualized in the Wazuh dashboard with full JSON telemetry.

📸 Screenshots
Below are snapshots of the full detection pipeline:

Sysmon installation terminal
![Image](https://github.com/user-attachments/assets/be30a170-5b04-4c57-8f98-b9fb00e19f4a)

ossec.conf edit to monitor Sysmon logs
![Image](https://github.com/user-attachments/assets/017c331b-3a0d-4eb9-bc44-a2f1186b126c)

PowerShell simulation of whoami and ping
![Image](https://github.com/user-attachments/assets/661203d6-4239-4c15-9d58-df82decddb98)

Wazuh alert dashboard showing MITRE mapping
![Image](https://github.com/user-attachments/assets/0210f315-e381-40b3-9cfa-7474fce41c66)

Wazuh JSON log view with full command-line, user, parent process, and hashes
![Image](https://github.com/user-attachments/assets/9266669e-0139-43a0-905e-04f579667ca7)
![Image](https://github.com/user-attachments/assets/dc19c1e4-dc70-4ba3-8909-42bf2a19b676)

Event Viewer confirming raw Sysmon logs
![Image](https://github.com/user-attachments/assets/25fc4d61-7f9e-4b79-88e3-71f936eedf07)


🧩 Skills Demonstrated
Endpoint visibility with Sysmon

SIEM integration and log forwarding

Log enrichment and MITRE ATT&CK mapping

Blue Team detection engineering practices

Real-world recon behavior simulation

