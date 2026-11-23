#!/usr/bin/env python3
"""Train and compare supervised network-intrusion classifiers on a labeled CSV.

Example:
  python ml/train_model.py --csv data/CIC-IDS2017.csv --label Label
"""
import argparse, json, re, sys, time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, classification_report,
    confusion_matrix, f1_score, precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

ID_PATTERN = re.compile(r'(^|[_\s-])(flow.?id|src.?ip|dst.?ip|source.?ip|destination.?ip|timestamp|date|time|row.?id|unnamed)([_\s-]|$)', re.I)

def main():
    ap = argparse.ArgumentParser(description='ShiftShield supervised IDS model trainer')
    ap.add_argument('--csv', required=True, help='Labeled network-flow CSV')
    ap.add_argument('--label', default='Label', help='Target column (default: Label)')
    ap.add_argument('--out', default='models', help='Output directory')
    ap.add_argument('--test-size', type=float, default=.2)
    ap.add_argument('--max-rows', type=int, default=250000, help='Deterministic cap for laptop-friendly training')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    path = Path(args.csv)
    if not path.is_file(): ap.error(f'CSV not found: {path}')
    print(f'[ShiftShield] Reading {path} ...')
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    if args.label not in df.columns:
        ap.error(f"Label column '{args.label}' not found. Available columns: {', '.join(df.columns[:30])}")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=[args.label])
    if len(df) > args.max_rows:
        df = df.sample(args.max_rows, random_state=args.seed)
    y_raw = df[args.label].astype(str).str.strip()
    X = df.drop(columns=[args.label])
    # CIC-style flow data should be numeric; drop obvious identifiers and non-numeric columns.
    drop_cols = [c for c in X.columns if ID_PATTERN.search(c) or not pd.api.types.is_numeric_dtype(X[c])]
    X = X.drop(columns=drop_cols, errors='ignore')
    X = X.apply(pd.to_numeric, errors='coerce')
    X = X.dropna(axis=1, how='all')
    X = X.loc[:, X.nunique(dropna=True) > 1]
    if X.empty: ap.error('No usable numeric feature columns remained after cleaning.')
    # Remove rows with no usable values across all features.
    keep = X.notna().any(axis=1)
    X, y_raw = X.loc[keep], y_raw.loc[keep]
    counts = y_raw.value_counts()
    rare = counts[counts < 2]
    if len(rare):
        ap.error('Each class needs at least 2 rows for a stratified split. Rare classes: ' + ', '.join(f'{k}={v}' for k,v in rare.items()))
    if y_raw.nunique() < 2: ap.error('At least two target classes are required.')
    enc = LabelEncoder(); y = enc.fit_transform(y_raw)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=args.test_size,
        random_state=args.seed, stratify=y)
    prep = SimpleImputer(strategy='median', add_indicator=False)
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=250, class_weight='balanced_subsample',
            n_jobs=-1, random_state=args.seed, min_samples_leaf=1),
        'Extra Trees': ExtraTreesClassifier(n_estimators=250, class_weight='balanced',
            n_jobs=-1, random_state=args.seed, min_samples_leaf=1),
        'Decision Tree': DecisionTreeClassifier(class_weight='balanced', random_state=args.seed,
            min_samples_leaf=2),
        'Logistic Regression': LogisticRegression(max_iter=1000, class_weight='balanced',
            solver='lbfgs', random_state=args.seed),
    }
    results=[]; fitted={}; best_name=None; best_score=-1
    for name, estimator in models.items():
        steps=[('imputer', SimpleImputer(strategy='median'))]
        if name == 'Logistic Regression': steps.append(('scale', StandardScaler()))
        steps.append(('model', estimator)); pipe=Pipeline(steps)
        print(f'[ShiftShield] Training {name} ...')
        t0=time.perf_counter(); pipe.fit(X_train, y_train); train_s=time.perf_counter()-t0
        t0=time.perf_counter(); pred=pipe.predict(X_test); predict_s=time.perf_counter()-t0
        macro=f1_score(y_test,pred,average='macro',zero_division=0)
        row={'model':name,'accuracy':round(float(accuracy_score(y_test,pred)),5),
             'precision_macro':round(float(precision_score(y_test,pred,average='macro',zero_division=0)),5),
             'recall_macro':round(float(recall_score(y_test,pred,average='macro',zero_division=0)),5),
             'f1_macro':round(float(macro),5),'f1_weighted':round(float(f1_score(y_test,pred,average='weighted',zero_division=0)),5),
             'train_seconds':round(train_s,3),'predict_seconds':round(predict_s,3)}
        results.append(row); fitted[name]=pipe
        print(f"  macro-F1={macro:.4f}, accuracy={row['accuracy']:.4f}, train={train_s:.1f}s")
        if macro > best_score: best_score=macro; best_name=name
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    best=fitted[best_name]; best_pred=best.predict(X_test)
    artifact={'pipeline':best,'label_encoder':enc,'features':list(X.columns),
              'label_column':args.label,'classes':enc.classes_.tolist(),'model_name':best_name}
    joblib.dump(artifact,out/'shiftshield_model.joblib')
    joblib.dump(artifact,out/'threatlens_model.joblib')
    report={'project':'ShiftShield','dataset':path.name,'rows_used':int(len(X)),
        'train_rows':int(len(X_train)),'test_rows':int(len(X_test)),
        'features':list(X.columns),'dropped_columns':drop_cols,
        'class_distribution':{str(k):int(v) for k,v in y_raw.value_counts().items()},
        'models':results,'selected_model':best_name,
        'classification_report':classification_report(y_test,best_pred,target_names=enc.classes_.tolist(),output_dict=True,zero_division=0),
        'confusion_matrix':confusion_matrix(y_test,best_pred).tolist(),
        'confusion_matrix_labels':enc.classes_.tolist(),
        'warning':'Metrics are from a random stratified holdout. For stronger IDS evaluation, also test on a time-separated or day-separated split to reduce leakage.'}
    (out/'training_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(f'\n[ShiftShield] Best model: {best_name} (macro-F1 {best_score:.4f})')
    print(f"Saved: {out/'shiftshield_model.joblib'}")
    print(f"Report: {out/'training_report.json'}")

if __name__=='__main__':
    try: main()
    except (ValueError, KeyError) as e:
        print(f'[ShiftShield] Error: {e}',file=sys.stderr); sys.exit(2)
