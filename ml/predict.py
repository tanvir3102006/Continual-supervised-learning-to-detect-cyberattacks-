#!/usr/bin/env python3
"""Predict a single flow represented as JSON using the saved ShiftShield model."""
import argparse, json
from pathlib import Path
import joblib, pandas as pd

default_model = 'models/shiftshield_model.joblib' if Path('models/shiftshield_model.joblib').exists() else 'models/threatlens_model.joblib'
p = argparse.ArgumentParser(description='ShiftShield Flow Classifier')
p.add_argument('--model', default=default_model, help='Path to trained .joblib model')
p.add_argument('--json', default=None, help='JSON object of feature_name: numeric_value (optional, defaults to sample flow)')
a = p.parse_args()

if not Path(a.model).exists():
    raise SystemExit(f"[Error] Model file '{a.model}' not found. Run 'py ml/train_model.py --csv data/sample_network_flows.csv' first.")

artifact = joblib.load(a.model)

if a.json:
    obj = json.loads(a.json)
else:
    # Default demo flow (DoS flood pattern)
    obj = {
        "duration": 0.52,
        "srcBytes": 3.1,
        "dstBytes": 0.95,
        "connCount": 5.2,
        "sameSrvRate": 0.88,
        "errorRate": 0.72,
        "failedLogins": 0.0,
        "uniquePorts": 1.0,
        "srcIPs": 1.0,
        "payloadEntropy": 2.05
    }
    print("[ShiftShield] No --json argument provided. Using demo network flow:")
    print(json.dumps(obj, indent=2))
    print("\n--- Prediction Result ---")
row={name:obj.get(name,None) for name in artifact['features']}
X=pd.DataFrame([row],columns=artifact['features'])
pipeline=artifact['pipeline']; pred=int(pipeline.predict(X)[0]); label=str(artifact['label_encoder'].inverse_transform([pred])[0])
result={'prediction':label,'model':artifact['model_name']}
if hasattr(pipeline,'predict_proba'):
    probs=pipeline.predict_proba(X)[0]
    result['confidence']=round(float(max(probs)),4)
    result['class_probabilities']={str(c):round(float(v),4) for c,v in zip(artifact['label_encoder'].classes_,probs)}
print(json.dumps(result,indent=2))
