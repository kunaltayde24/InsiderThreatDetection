import random

def compute_risk(event: dict) -> float:
    """
    Fake ML risk score (replace with model later)
    """
    base = random.uniform(10, 60)

    if event.get("action") == "download":
        base += 20

    if event.get("off_hours"):
        base += 25

    return min(base, 100)
