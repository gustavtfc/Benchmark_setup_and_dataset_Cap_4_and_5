# Zero-Shot Vulnerability Detection (SAST) Benchmark for Open-Weight LLMs

This repository contains the source code, datasets, and orchestration scripts used in the empirical evaluation of a Master's dissertation in Informatics Engineering (Cybersecurity). The goal of this framework is to benchmark **open-weight Large Language Models (LLMs)** for **zero-shot static vulnerability detection (SAST-style classification)** across two ecosystems:

- **C/C++ (system-level)**: `glibc`
- **Java (managed, object-oriented)**: `CWE-Bench-Java`

---

## Project Layout

The project is organized as a modular, language-agnostic pipeline that separates data ingestion, inference, and results analysis:

- **`/data`**: Raw and processed dataset files.
- **`/prompts`**: Zero-shot prompt templates designed to enforce deterministic outputs (JSON schema).
- **`/results`**: Metrics and extracted outputs, split by ecosystem (`/CWE_Java` and `/Glibc`).
- **`/scripts`**: Core orchestration and tooling (described below).
- **`benchmark_completo.log`**: Log file with telemetry from the most recent full run.

---

## Scripts Overview (`/scripts`)

To support auditability and reproducibility, responsibilities are split across dedicated scripts:

### 1) Data Ingestion and Preparation

- **`fetch_code_GLIBC.py`**: Connects to the UC/DEI database to extract and format the C/C++ (`glibc`) dataset.
- **`fetch_code_CWE_Bench_Java.py`**: Downloads and prepares the Java (`CWE-Bench-Java`) dataset.
- **`separar_datasets.py`**: Performs a logical split between vulnerable and patched code.
- **`extrair_amostras.py`**: Extracts representative subsets for quick tests and pipeline validation.

### 2) Orchestration and Inference

- **`run_benchmark_DEI.py`**: **Main entry point.** Orchestrates the full pipeline: loads prompts, iterates over datasets, and runs temperature ablation (`T ∈ {0.0, 0.2, 0.5}`).
- **`interrogar_llm.py`**: Helper module for strict HTTP requests to the local Ollama API (credentials + timeouts).
- **`check_models.py`**: Pre-flight validation to confirm that all required models (Qwen, DeepSeek, CodeLlama, etc.) are available on the local cluster before launching the benchmark.
- **`sonda_qwen36.py`**: Isolated diagnostic script to test connectivity, payload format, and raw model responses (without parsing) for specific models.

### 3) Monitoring and Telemetry

- **`live_analyzer.py`**: Real-time analyzer and RegEx validator. Parses the LLM-generated JSON, sanitizes strings (e.g., CWE formatting), and reports parsing failures.
- **`radar_gpu.py`**: Monitors GPU VRAM usage and compute spikes in real time to track computational efficiency.
- **`merge_temps.py`**: Consolidates the `.csv` files produced at different temperatures (0.0, 0.2, 0.5) into a single structured report.

---

## How to Run (Reproducibility Guide)

To reproduce the methodology described in **Chapter 5** of the dissertation:

1. **Environment setup**  
   Make sure the Ollama server is running on the local cluster and that the 7 models are already pulled/loaded.

2. **Pre-flight check**  
   Run:
   ```bash
   python scripts/check_models.py
