import re
import numpy as np
import pandas as pd
import tldextract  
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse, urlunparse  
import requests    
import whois       
import pickle      
import os
import sys

class PhishingDetector:
    def __init__(self):
        
        self.model_path = 'models/phishing_model.pkl'
        self.keywords = [
            'login', 'signin', 'secure', 'account', 
            'verify', 'banking', 'update', 'password'
        ]
        self.load_model()
    
    def load_model(self):
        
        if not os.path.exists(self.model_path):
            print("Error: Model tidak ditemukan!")
            print("Jalankan 'python train_model.py' terlebih dahulu")
            sys.exit(1)
        
        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)
    
    def extract_features(self, url):
      
        features = {}
        parsed = urlparse(url)
        
      
        features['url_length'] = len(url)
        
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        
        features['num_special_chars'] = len(
            re.findall(r'[!@#$%^&*()\-_=+\[\]{};:\'",<>/?\\|]', url)
        )
        
        features['has_ip'] = 1 if re.match(
            r'\d+\.\d+\.\d+\.\d+', parsed.netloc
        ) else 0
        
        ext = tldextract.extract(url)
        features['num_subdomains'] = len(ext.subdomain.split('.')) 
        
        features['domain_age'] = self.get_domain_age(parsed.netloc)
        
        features['keyword_count'] = sum(
            1 for word in self.keywords if word in url.lower()
        )
        
        
        features['has_redirect'] = 1 if '//' in url.split('://', 1)[1] else 0
        
        
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        return pd.DataFrame([features])
    
    def get_domain_age(self, domain):
        
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
          
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            return (datetime.now() - creation_date).days
        except:
            return 30 
    
    def check_url(self, url):
        
        try:
            
            features = self.extract_features(url)
            
            
            pred = self.model.predict(features)[0]
            proba = self.model.predict_proba(features)[0][1]
            
          
            return {
                'url': url,
                'prediction': 'PHISHING' if pred == 1 else 'AMAN',
                'confidence': f"{proba*100:.2f}%",
                'is_phishing': pred == 1
            }
        except Exception as e:
            print(f"Error: {e}")
            return None

if __name__ == "__main__":
  
    if len(sys.argv) != 2:
        print("Penggunaan: python detector.py <URL>")
        sys.exit()
    
    detector = PhishingDetector()
    result = detector.check_url(sys.argv[1])
    
    print("\n=== HASIL DETEKSI ===")
    print(f"URL: {result['url']}")
    print(f"Hasil: {result['prediction']}")
    print(f"Kepercayaan: {result['confidence']}")
    print("=====================")