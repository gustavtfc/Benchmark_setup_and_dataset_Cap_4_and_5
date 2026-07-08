import pandas as pd
import json
import glob

# Automatically find the latest results file
result_files = glob.glob('results/vulnerability_test_results_*.json')
if not result_files:
    raise FileNotFoundError("No results files found in 'results/' directory.")

results_file = max(result_files)

# Open JSON and load as list of dicts
with open(results_file, 'r', encoding='utf-8') as f:
    data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Result JSON is not a list. Check your test script output.")
df = pd.DataFrame(data)

# Overview
print(f"Loaded file: {results_file}")
print(f"Total records: {len(df)}")
print("Models tested:", df['model'].unique())
print("Prompt variants:", df['prompt_variant'].unique())

# 1. Detection Rate per Model
by_model = df.groupby("model")
success_rate = by_model["success"].mean() * 100
print("\n--- Detection Success Rate per Model (%):")
print(success_rate)

# 2. Correct Vulnerability Type (very basic keyword match)
def correct_vuln_detected(row):
    if pd.isna(row.get("expected_vuln_type")) or pd.isna(row.get("response")):
        return False
    return any(
        word.strip().lower() in row['response'].lower()
        for word in str(row['expected_vuln_type']).replace('<', '').replace('>', '').split('<>')
        if word.strip()
    )

df["correct_type"] = df.apply(correct_vuln_detected, axis=1)
type_rate = by_model["correct_type"].mean() * 100
print("\n--- Correct Vulnerability Type Rate per Model (%):")
print(type_rate)

# 3. Average Response Time
print("\n--- Average Response Time per Model (s):")
print(by_model["response_time"].mean())

# 4. 1.5B vs 7B; Coder vs Base Comparison
def model_class(model_name):
    if "coder" in model_name:
        return "Coder"
    return "Base"

def model_size(model_name):
    if "7b" in model_name:
        return "7B"
    elif "1.5b" in model_name:
        return "1.5B"
    elif "14b" in model_name:
        return "14B"
    return "Other"

df["model_class"] = df["model"].apply(model_class)
df["model_size"] = df["model"].apply(model_size)

print("\n--- Performance by Model Type:")
perf_tab = df.groupby(["model_class", "model_size"]).agg(
    DetectionRate=("success", "mean"),
    TypeAcc=("correct_type", "mean"),
    AvgTime=("response_time", "mean"),
    Count=("success", "count")
)
print(perf_tab)

# 5. Save summary table for academic report
summary_df = perf_tab.reset_index()
summary_df["DetectionRate"] = summary_df["DetectionRate"] * 100
summary_df["TypeAcc"] = summary_df["TypeAcc"] * 100
summary_df.to_csv("results/model_performance_summary.csv", index=False)
print("\nSummary saved at 'results/model_performance_summary.csv'")

# 6. Optional: Visualize (requires matplotlib)
try:
    import matplotlib.pyplot as plt
    success_rate.sort_values().plot(kind="barh", title="Detection Rate by Model")
    plt.xlabel("Detection Rate (%)")
    plt.show()
except Exception as e:
    print("Visualization skipped (matplotlib may not be available):", e)
