import pandas as pd
import os
import glob

def analyze_live_results(vuln_path, patched_path, model_name="Model"):
    print(f"\n" + "="*60)
    print(f" 📊 LIVE ANALYSIS REPORT: {model_name}")
    print("="*60)

    try:
        df_vuln = pd.read_csv(vuln_path)
        df_patched = pd.read_csv(patched_path)
    except Exception as e:
        print(f"❌ Error loading files: {e}")
        return

    # 1. Filter out API and Parse Errors
    error_flags = ['API_ERROR', 'PARSE_ERROR', 'SKIPPED_SIZE']
    vuln_valid = df_vuln[~df_vuln['predicted_cwe'].isin(error_flags)].copy()
    patched_valid = df_patched[~df_patched['predicted_cwe'].isin(error_flags)].copy()

    vuln_errors = len(df_vuln) - len(vuln_valid)
    patched_errors = len(df_patched) - len(patched_valid)

    # 2. Analyze Vulnerable Dataset
    cwe_exact_matches = 0
    if len(vuln_valid) > 0:
        vuln_preds = vuln_valid['predicted_is_vulnerable'].astype(str).str.lower() == 'true'
        tp = vuln_preds.sum()
        fn = len(vuln_preds) - tp
        tp_pct = (tp / len(vuln_valid)) * 100
        fn_pct = (fn / len(vuln_valid)) * 100
        
        # CWE Logic
        tp_df = vuln_valid[vuln_preds]
        if tp > 0:
            tp_expected = tp_df['expected_cwe'].astype(str).str.strip().str.upper()
            tp_predicted = tp_df['predicted_cwe'].astype(str).str.strip().str.upper()
            cwe_exact_matches = (tp_expected == tp_predicted).sum()
        cwe_accuracy = (cwe_exact_matches / tp * 100) if tp > 0 else 0
    else:
        tp = fn = tp_pct = fn_pct = cwe_accuracy = 0

    # 3. Analyze Patched Dataset
    if len(patched_valid) > 0:
        patched_preds = patched_valid['predicted_is_vulnerable'].astype(str).str.lower() == 'true'
        fp = patched_preds.sum()
        tn = len(patched_preds) - fp
        fp_pct = (fp / len(patched_valid)) * 100
        tn_pct = (tn / len(patched_valid)) * 100
        
        # CWE Logic
        fp_df = patched_valid[patched_preds]
        top_hallucinated = fp_df['predicted_cwe'].astype(str).str.strip().str.upper().value_counts().head(3)
    else:
        fp = tn = fp_pct = tn_pct = 0
        top_hallucinated = pd.Series(dtype=int)

    # 4. Print Vulnerable Breakdown
    print(f"\n🛑 VULNERABLE DATASET (Expected Output: True / Vulnerable)")
    print(f"   Total valid samples: {len(vuln_valid)} (Bypassed {vuln_errors} API/Parse errors)")
    print(f"   ➤ PREDICTED TRUE  (True Positives):  {tp} samples ({tp_pct:.1f}%)")
    print(f"   ➤ PREDICTED FALSE (False Negatives): {fn} samples ({fn_pct:.1f}%)")

    # 5. Print Patched Breakdown
    print(f"\n✅ PATCHED DATASET (Expected Output: False / Safe)")
    print(f"   Total valid samples: {len(patched_valid)} (Bypassed {patched_errors} API/Parse errors)")
    print(f"   ➤ PREDICTED FALSE (True Negatives):  {tn} samples ({tn_pct:.1f}%)")
    print(f"   ➤ PREDICTED TRUE  (False Positives): {fp} samples ({fp_pct:.1f}%)")

    # 6. Overall Metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print(f"\n📈 OVERALL PERFORMANCE METRICS")
    print(f"   Precision:             {precision:.2%}")
    print(f"   Recall (Sensitivity):  {recall:.2%}")
    print(f"   F1-Score:              {f1:.2%}")
    print(f"   False Positive Rate:   {fpr:.2%}")
    
    if 'latency_ms' in vuln_valid.columns and 'latency_ms' in patched_valid.columns:
        print(f"   Avg Latency (Vuln):    {vuln_valid['latency_ms'].mean():.2f} ms")
        print(f"   Avg Latency (Patched): {patched_valid['latency_ms'].mean():.2f} ms")

    # 7. Print CWE Diagnostic Analysis
    print(f"\n🎯 CWE DIAGNOSTIC ANALYSIS")
    print(f"   [Vulnerable Code] CWE Match Rate on True Positives:")
    print(f"   ➤ The model correctly identified the exact CWE in {cwe_exact_matches} out of {tp} detected vulnerabilities ({cwe_accuracy:.1f}% accuracy).")
    
    if len(top_hallucinated) > 0:
        print(f"\n   [Patched Code] Top Hallucinated CWEs (False Positives Bias):")
        for cwe, count in top_hallucinated.items():
            print(f"   ➤ {cwe}: {count} times")
    else:
        print(f"\n   [Patched Code] No hallucinated CWEs (0 False Positives).")

    # 8. Print Temperature Impact Analysis 
    print(f"\n🌡️ TEMPERATURE IMPACT ANALYSIS")
    if 'temperature' in vuln_valid.columns and 'temperature' in patched_valid.columns:
        temps = sorted(list(set(vuln_valid['temperature'].dropna().unique()) | set(patched_valid['temperature'].dropna().unique())))
        
        if len(temps) > 0:
            print(f"   Comparing model performance across recorded temperatures:")
            for t in temps:
                v_t = vuln_valid[vuln_valid['temperature'] == t]
                p_t = patched_valid[patched_valid['temperature'] == t]
                
                # Metrics specifically for this temperature
                tp_t = (v_t['predicted_is_vulnerable'].astype(str).str.lower() == 'true').sum() if len(v_t) > 0 else 0
                fn_t = len(v_t) - tp_t
                
                fp_t = (p_t['predicted_is_vulnerable'].astype(str).str.lower() == 'true').sum() if len(p_t) > 0 else 0
                tn_t = len(p_t) - fp_t
                
                prec_t = tp_t / (tp_t + fp_t) if (tp_t + fp_t) > 0 else 0
                rec_t = tp_t / (tp_t + fn_t) if (tp_t + fn_t) > 0 else 0
                f1_t = 2 * (prec_t * rec_t) / (prec_t + rec_t) if (prec_t + rec_t) > 0 else 0
                
                print(f"   ➤ Temp {t}: Precision {prec_t:.1%} | Recall {rec_t:.1%} | F1-Score {f1_t:.1%} (Samples: Vuln={len(v_t)}, Patched={len(p_t)})")
        else:
            print("   ➤ No valid temperature data found in the column.")
    else:
        print("   ➤ 'temperature' column not found in datasets. If you used separate files for 0.0 and 0.2, run this script individually on those files to compare.")

    print("="*60 + "\n")

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.dirname(SCRIPT_DIR)
    RESULTS_DIR = os.path.join(BASE_DIR, "results")
    
    # =========================================================================
    MODEL_SEARCH_TERM = "Qwen2.5-coder_14b"  # Modelos
    DISPLAY_NAME = "Qwen2.5-coder(14b)"
    # =========================================================================
    
    search_vuln = os.path.join(RESULTS_DIR, f"*{MODEL_SEARCH_TERM}*Vulnerable*.csv")
    search_patched = os.path.join(RESULTS_DIR, f"*{MODEL_SEARCH_TERM}*Patched*.csv")
    
    vuln_files = sorted(glob.glob(search_vuln))
    patched_files = sorted(glob.glob(search_patched))
    
    if vuln_files and patched_files:
        analyze_live_results(vuln_files[-1], patched_files[-1], model_name=DISPLAY_NAME)
    else:
        print(f"❌ Error: Missing files for '{MODEL_SEARCH_TERM}'. Checked {RESULTS_DIR}")