# Educational rule-based ML-style classifier.
# Replace this function with a trained scikit-learn model for production research.
def classify_traffic(d):
    score=0
    if d["packets"] > 1800: score += 3
    if d["bytes"] > 900000: score += 2
    if d["duration"] < 1 and d["packets"] > 500: score += 2
    if d["port"] in [21,23,445,3389]: score += 1
    if d["protocol"].upper() == "ICMP" and d["packets"] > 1200: score += 2

    if score >= 6:
        attack, sev, conf="DDoS","Critical",0.96
    elif score >= 4:
        attack, sev, conf="Port Scan","High",0.89
    elif score >= 2:
        attack, sev, conf="Suspicious Activity","Medium",0.78
    else:
        attack, sev, conf="Normal","Low",0.94
    return {"attack_type":attack,"severity":sev,"confidence":conf}
