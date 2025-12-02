\
import joblib
import numpy as np
import datetime
import os
import re

class ThreatDetectionAgent:
    def __init__(self, model_path="model.joblib"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}. Run python train.py first.")
        self.model = joblib.load(model_path)

    def detect(self, df):
        preds = self.model.predict(df)
        proba = None
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(df)[:, 1]
        return preds, proba

class ThreatIntelAgent:
    def classify_severity(self, row):
        try:
            if row.get("failed_logins", 0) >= 4:
                return "HIGH", "Brute-force login activity detected."
            if row.get("src_bytes", 0) > 1500:
                return "HIGH", "Possible DoS attack (large packet burst)."
            if row.get("hot", 0) > 5:
                return "MEDIUM", "Suspicious scanning detected."
            if int(row.get("pred", 0)) == 1:
                return "LOW", "Weak attack signature detected."
        except Exception:
            pass
        return "NONE", "Normal traffic."

    def analyze(self, df):
        sev = []
        info = []
        for _, row in df.iterrows():
            s, t = self.classify_severity(row)
            sev.append(s)
            info.append(t)
        df["severity"] = sev
        df["analysis"] = info
        return df

class AutoResponseAgent:
    def __init__(self, logfile="agent_logs.txt"):
        self.logfile = logfile

    def respond(self, df):
        """
        Default rule-based actions (keeps existing behavior).
        RL will be able to override later by calling apply_action per row.
        """
        actions = []
        logs = []
        for _, row in df.iterrows():
            if row["severity"] == "HIGH":
                action = "BLOCK SOURCE IP"
            elif row["severity"] == "MEDIUM":
                action = "RATE LIMIT"
            elif row["severity"] == "LOW":
                action = "MONITOR"
            else:
                action = "NO ACTION"
            actions.append(action)
            logs.append(f"{datetime.datetime.now()} | {action} | {row.to_dict()}\n")
        df["action"] = actions
        with open(self.logfile, "a", encoding="utf-8") as f:
            f.writelines(logs)
        return df

    def apply_action(self, row, action_str):
        """
        Called by RL agent to perform/record a selected action.
        This function should implement the real effect (block IP, alert, etc).
        For safety, we only log actions here. You can expand to call firewall commands.
        Return a dict describing what was done.
        """
        now = datetime.datetime.now()
        src_ip = row.get("src_ip", row.get("top_ip", "unknown_ip"))
        entry = f"{now} | ACTION({action_str}) | src_ip={src_ip} | row_pred={row.get('pred')} | severity={row.get('severity')}\n"
        with open(self.logfile, "a", encoding="utf-8") as f:
            f.write(entry)

        # Simulated effect: return a simple result
        result = {
            "action": action_str,
            "src_ip": src_ip,
            "timestamp": str(now),
            "note": "logged (no real block executed)"
        }

        # If you want to actually block an IP (risky), implement system command here
        # e.g. call firewall or iptables (NOT recommended without admin safety checks)
        return result

class SelfEvolvingAgent:
    def __init__(self, threshold=0.85):
        self.threshold = threshold

    def check_and_retrain(self, accuracy):
        if accuracy >= self.threshold:
            return False, "Accuracy OK. No retraining."
        # Auto retrain - note: this will run train.py
        from train import train_and_save_model
        train_and_save_model()
        return True, "Model retrained."

class SystemMonitorAgent:
    def get_cpu_usage(self):
        """Reliable CPU usage via PowerShell"""
        try:
            out = os.popen(
                "powershell.exe (Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples.CookedValue"
            ).read()
            return int(float(out.strip()))
        except:
            return 0

    def get_memory_free(self):
        """Free RAM in MB via PowerShell"""
        try:
            out = os.popen(
                "powershell.exe (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"
            ).read()
            return int(out.strip()) // 1024
        except:
            return 0

    def scan_netstat(self):
        """Parses YOUR Windows netstat format accurately"""
        out = os.popen("netstat -ano").read()
        lines = out.splitlines()

        syn_count = 0
        ips = {}

        for line in lines:
            line = line.strip()
            if not line.startswith("TCP"):
                continue  # skip UDP and headers

            parts = line.split()
            if len(parts) < 4:
                continue

            local = parts[1]
            remote = parts[2]
            state = parts[3]

            # --- Detect SYN states ---
            if "SYN" in state.upper():
                syn_count += 1

            # --- Extract IPv4 and IPv6 addresses ---
            import re
            # match either IPv4:port OR [IPv6]:port
            match = re.findall(r"(\d+\.\d+\.\d+\.\d+)|(\[[0-9A-Fa-f:]+\])", remote)
            if match:
                # match gives tuples, use the non-empty group
                ipv4 = match[0][0]
                ipv6 = match[0][1].strip("[]") if match[0][1] else None
                ip = ipv4 if ipv4 else ipv6
                ips[ip] = ips.get(ip, 0) + 1

        top_ip = max(ips, key=ips.get) if ips else None

        return {
            "syn_count": syn_count,
            "connections": ips,
            "top_ip": top_ip
        }

    def monitor(self):
        net = self.scan_netstat()
        return {
            "cpu": self.get_cpu_usage(),
            "free_ram_mb": self.get_memory_free(),
            "syn_count": net["syn_count"],
            "top_ip": net["top_ip"],
            "connections": net["connections"]
        }

