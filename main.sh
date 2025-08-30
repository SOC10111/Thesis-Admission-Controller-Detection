#!/bin/bash
# Main orchestrator for Falco-based malicious admission controller detection
# Analyzes real Falco security events to identify malicious admission webhooks
#
# This script serves as the main entry point for the ML detection system.
# It coordinates the deployment of test admission controllers, collection of
# Falco security events, training of ML models, and management of the detection
# system lifecycle.

# Enable strict error handling to catch issues early
set -euo pipefail

# Store the script's directory path for accessing other project files
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load shared utility functions (logging, error handling, etc.)
source "${SCRIPT_DIR}/lib/utils.sh"
# Load system configuration constants (namespaces, file paths, etc.)
source "${SCRIPT_DIR}/config/constants.sh"

# Display usage information and available commands to the user
show_usage() {
    cat <<USAGE
ML-Enhanced Detection of Malicious Kubernetes Admission Controllers using Falco
================================================================================

Usage: $0 [COMMAND]

Commands:
    deploy-baseline              - Deploy baseline admission controllers and collect Falco logs
    train-baseline               - Train ML models on baseline data
    deploy-malicious-controller  - Deploy malicious admission controller and collect logs
    train                        - Train ML on custom JSON file (prompts for path)
    feedback                     - Review and manage ML feedback
    cleanup                      - Comprehensive cleanup of all project resources
 
Output Directory: ./test-results/
USAGE
}

# All ML functionality is delegated to specialized scripts in the setup/ directory

# Initialize the environment for ML training by creating necessary directories
# and deploying baseline admission controllers
setup_environment() {
    log_info "=== SETTING UP ENVIRONMENT ==="
    
    # Create the directory where ML models, databases, and training data will be stored
    log_info "Creating test-results directory..."
    mkdir -p "${TEST_RESULTS_DIR}"
    
    # Deploy 4 baseline admission controllers to generate normal behavior patterns
    log_info "Deploying baseline environment and collecting logs..."
    "${SCRIPT_DIR}/setup/deploy_baseline.sh"
    
    log_info "Environment setup completed"
}

# Verify that all required components are available before running ML operations
verify_system() {
    log_info "=== VERIFYING SYSTEM READINESS ==="
    
    # Verify Python ML libraries are installed (scikit-learn for models, pandas for data processing)
    log_info "Checking ML dependencies..."
    python3 -c "import sklearn, pandas, numpy, joblib; print('ML dependencies available')" 2>/dev/null || log_warn "ML dependencies missing - run: pip install scikit-learn pandas numpy joblib"
    
    # Verify kubectl can connect to the Kubernetes cluster
    kubectl version --client >/dev/null 2>&1 && log_info "Kubernetes CLI available" || log_warn "kubectl not available"
    
    # Check that the core ML analysis script exists
    if [ -f "${SCRIPT_DIR}/analysis/admission_controller_ml.py" ]; then
        log_info "Falco ML analyzer available"
    else
        log_warn "Falco ML analyzer missing"
    fi
    
    # Verify Falco is deployed and running in the cluster to provide security events
    if kubectl get pods -n falco -l app.kubernetes.io/name=falco >/dev/null 2>&1; then
        log_info "Falco pod accessible"
    else
        log_warn "Falco pod not accessible"
    fi
    
    log_info "System verification completed"
}

# Main function that processes user commands and delegates to appropriate scripts
main() {
    # Get the command from first argument, default to empty string if not provided
    local command="${1:-}"
    
    case "$command" in
        # ML workflow commands
        deploy-baseline)
            # Deploy 4 baseline admission controllers and collect 10 minutes of Falco events
            "${SCRIPT_DIR}/setup/deploy_baseline.sh"
            ;;
        train-baseline)
            # Train ML models using the collected baseline data from deploy-baseline
            "${SCRIPT_DIR}/setup/train_baseline.sh"
            ;;
        deploy-malicious-controller)
            # Deploy a test malicious admission controller for 600 seconds (10 minutes)
            "${SCRIPT_DIR}/setup/deploy_malicious_admission_controller.sh" deploy 600
            ;;
        train)
            # Train ML models on a custom Falco JSON log file provided by the user
            # Prompt user for JSON file path
            read -p "Enter path to Falco JSON log file: " input_path
            
            # Ensure the file exists before attempting to process it
            if [ ! -f "$input_path" ]; then
                echo "ERROR: File does not exist: $input_path"
                exit 1
            fi
            
            # Ensure the file has content (not empty)
            if [ ! -s "$input_path" ]; then
                echo "ERROR: File is empty: $input_path"
                exit 1
            fi
            
            # Delegate to the custom training script with the validated file path
            "${SCRIPT_DIR}/setup/train_custom.sh" "$input_path"
            ;;
        feedback)
            # Interactive review system to correct ML classifications
            # Check if the ML database exists (created during training)
            if [ ! -f "${TEST_RESULTS_DIR}/${ML_DATABASE_FILE}" ]; then
                echo "No detection database found. Please train a model first."
                exit 1
            fi
            
            # Launch the interactive feedback review interface
            "${SCRIPT_DIR}/setup/feedback_review.sh"
            ;;
            
        # Infrastructure commands
        cleanup)
            # Remove all project resources to prepare for a fresh run
            log_info "=== COMPREHENSIVE CLEANUP ==="
            log_info "Cleaning up all project resources and data..."
            
            # Execute the cleanup script with force flag to remove all resources
            if "${SCRIPT_DIR}/utils/cleanup.sh" --force; then
                log_info "Cleanup completed successfully"
                
                # Double-check that all resources were properly removed
                log_info "Verifying cleanup completion..."
                "${SCRIPT_DIR}/utils/cleanup.sh" --verify-only
                
                # Provide summary of what was cleaned up
                log_info "=== CLEANUP SUMMARY ==="
                log_info "Webhook configurations removed"
                log_info "Test pods and deployments removed"
                log_info "Test namespaces removed"
                log_info "Background processes terminated"
                log_info "ML databases emptied (structure preserved)"
                log_info "Temporary files and certificates removed"
                log_info "ConfigMaps and Secrets removed"
                log_info ""
                log_info "System is ready for fresh ML training runs"
            else
                log_error "Cleanup failed - some resources may still exist"
                log_info "Run './utils/cleanup.sh --verify-only' to check remaining resources"
                exit 1
            fi
            ;;
            
        *)
            # No valid command provided, show usage help
            show_usage
            ;;
    esac
}

# Only execute main function if this script is run directly (not sourced)
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
