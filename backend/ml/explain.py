def explain_event(event, risk, ml_score):
    reasons = []

    # 🔥 Rule-based explanations
    if event.get("file_sensitive"):
        reasons.append("Accessed sensitive file")

    if event.get("malicious_process"):
        reasons.append("Malicious process detected")

    if event.get("duration_sec", 0) < 3:
        reasons.append("Very short activity duration")

    # 🔥 ML-based explanation
    if ml_score < -0.5:
        reasons.append("Strong anomaly detected by AI")
    elif ml_score < -0.2:
        reasons.append("Moderate anomaly detected by AI")

    # 🔥 Fallback
    if not reasons:
        reasons.append("Normal behavior")

    return reasons