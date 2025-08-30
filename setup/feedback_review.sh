#!/bin/bash

# Feedback Review System
# Interactive interface for reviewing and correcting ML predictions
#
# This script launches an interactive session where users can:
# 1. View all admission controllers detected by the ML system
# 2. See their current classifications (LEGITIMATE/SUSPICIOUS/MALICIOUS)
# 3. Provide corrections for misclassified controllers
# 4. Add comments explaining the corrections
#
# Feedback is stored in the ml_feedback_overrides table and persists
# across sessions. Note that models must be manually retrained to
# incorporate the feedback into future predictions.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Starting ML feedback review..."

# Launch the interactive Python feedback interface
cd "$PROJECT_DIR"
python3 analysis/admission_controller_ml.py feedback-review

echo "Feedback review completed"