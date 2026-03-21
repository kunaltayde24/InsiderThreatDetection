from ml.anomaly_model import train
import numpy as np

# fake normal data (replace with real logs later)
X = np.random.normal(loc=0, scale=1, size=(500, 4))

train(X)
print("✅ ML model trained")
