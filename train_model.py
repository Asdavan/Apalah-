"""
Script untuk melatih model dan menyimpan ke file .pkl
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import os
os.makedirs('models', exist_ok=True)
data = {
    'url_length': [50, 70, 30, 90, 100, 45, 80],
    'has_https': [1, 0, 1, 0, 1, 0, 1],
    'num_special_chars': [3, 7, 2, 9, 5, 4, 8],
    'has_ip': [0, 1, 0, 1, 0, 1, 0],
    'num_subdomains': [1, 3, 0, 2, 1, 0, 4],
    'domain_age': [365, 5, 200, 10, 600, 15, 3],
    'keyword_count': [1, 3, 0, 2, 1, 4, 0],
    'has_redirect': [0, 1, 0, 1, 0, 1, 0],
    'has_at_symbol': [0, 1, 0, 1, 0, 1, 0],
    'label': [0, 1, 0, 1, 0, 1, 1]
}

df = pd.DataFrame(data)

X = df.drop('label', axis=1)
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=5,
    random_state=42
)
model.fit(X_train, y_train)

with open('models/phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model berhasil dilatih!")