#!/bin/bash

# Train ML Models on Baseline Data
# Trains admission controller ML models using baseline.json
#
# This script processes the Falco events collected from the 4 baseline
# admission controllers and trains the ML models (Random Forest + Isolation Forest).
# The training process:
# 1. Parses events from baseline.json
# 2. Filters for admission controller events only
# 3. Extracts 43 behavioral features from each event
# 4. Auto-labels events based on calculated risk scores
# 5. Trains the dual ML models
# 6. Saves models to .pkl file and results to SQLite database

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Training ML models on baseline data..."

# Ensure the baseline data file exists from the deployment phase
BASELINE_FILE="$PROJECT_DIR/test-results/baseline.json"
if [ ! -f "$BASELINE_FILE" ]; then
    echo "ERROR: baseline.json not found. Run 'deploy-baseline' first."
    exit 1
fi

# Execute the ML training pipeline on the collected baseline data
echo "Training ML model..."
cd "$PROJECT_DIR"
python3 analysis/admission_controller_ml.py train-from-json --input ./test-results/baseline.json

# Verify that all expected output files were created successfully
echo "Verifying model outputs..."
if [ ! -f "./test-results/ml_admission_controller_ident.pkl" ]; then
    echo "ERROR: Model file not created"
    exit 1
fi

if [ ! -f "./test-results/ml_admission_controller_ident.db" ]; then
    echo "ERROR: Database file not created"
    exit 1
fi

echo "Model and database created successfully"

# The training process automatically generates a detailed analysis report
echo "Training report with ML factors: ./test-results/baseline_training_report.txt"

echo "Baseline training completed successfully"