import joblib
import os

BASE_DIR = os.path.dirname(__file__)

def get_models():
    iso = joblib.load(os.path.join(BASE_DIR, "isolation_forest.pkl"))
    ae = joblib.load(os.path.join(BASE_DIR, "autoencoder.pkl"))
    return iso, ae
