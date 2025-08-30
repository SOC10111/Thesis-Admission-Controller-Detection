# =============================================================================
# CONFIGURATION: config/constants.sh
# All configuration constants in one place
# =============================================================================

#!/bin/bash
# Configuration constants - DO NOT MODIFY DURING RUNTIME
# This file centralizes all configuration values used throughout the ML detection system

# Prevent this file from being sourced multiple times
[[ -n "${CONSTANTS_LOADED:-}" ]] && return 0
readonly CONSTANTS_LOADED=1

# Kubernetes namespaces used by the system
readonly FALCO_NAMESPACE="falco"                  # Where Falco is deployed for event monitoring
readonly BASELINE_NAMESPACE="baseline-test"       # Namespace for legitimate admission controllers
readonly MALICIOUS_NAMESPACE="monitoring-system"  # Namespace for test malicious controllers

# Container images and external resources
readonly WEBHOOK_IMAGE="python:3.9-alpine"        # Base image for admission controller containers
readonly FALCO_CHART_REPO="https://falcosecurity.github.io/charts"  # Helm repository for Falco

# Names for malicious test resources
readonly MALICIOUS_DEPLOYMENT_NAME="monitoring-agent"  # Deployment name for malicious controller
readonly MALICIOUS_SERVICE_NAME="monitoring-agent"     # Service name for malicious webhook
readonly MALICIOUS_CONFIG_NAME="monitoring-agent-webhook"  # ConfigMap name for malicious code
readonly TEST_POD_NAME="security-test-pod"            # Test pod to trigger webhooks

# Operation timeouts to prevent hanging
readonly DEFAULT_TIMEOUT="120s"       # Default timeout for operations
readonly POD_READY_TIMEOUT="60s"      # Max wait time for pods to become ready
readonly DEPLOYMENT_TIMEOUT="180s"    # Max wait time for deployments

# TLS certificate paths and filenames
readonly CERT_DIR="./certs"          # Directory to store generated certificates
readonly CA_KEY_FILE="ca.key"        # Certificate Authority private key
readonly CA_CERT_FILE="ca.crt"       # Certificate Authority certificate
readonly SERVER_KEY_FILE="server.key"    # Webhook server private key
readonly SERVER_CERT_FILE="server.crt"   # Webhook server certificate

# Test output and logging configuration
readonly TEST_RESULTS_DIR="./test-results"  # Main directory for all ML outputs
readonly LOG_RETENTION_DAYS=7               # How long to keep logs

# Falco event collection settings
readonly FALCO_LOG_PATH="/var/log/falco.log"  # Path to Falco log file in container
readonly FALCO_JSON_OUTPUT="true"             # Enable JSON output for ML parsing
readonly FALCO_PRIORITY="debug"               # Log level for detailed events

# ML analysis directory structure
readonly ML_EVENTS_DIR="${TEST_RESULTS_DIR}/ml_events"      # Raw event storage
readonly ML_ANALYSIS_DIR="${TEST_RESULTS_DIR}/ml_analysis"  # Analysis results
readonly ANALYSIS_OUTPUT_DIR="${TEST_RESULTS_DIR}"          # Final output location

# The 4 baseline admission controllers used for training
# These represent normal/legitimate admission controller behavior
readonly BASELINE_CONTROLLERS=(
    "cert-manager-webhook"         # Mutating - Injects TLS certificates into pods
    "istio-sidecar-injector"       # Mutating - Adds Envoy proxy sidecars for service mesh
    "resource-quota-webhook"       # Mutating - Enforces resource limits and requests
    "security-policy-validator"    # Validating - Checks security policies (privileged, root, etc.)
)

# ML model configuration parameters
readonly ML_FEATURE_COUNT=43                          # Number of features extracted per event
readonly ML_RISK_THRESHOLD_MALICIOUS=0.7             # Risk score >= 0.7 = MALICIOUS
readonly ML_RISK_THRESHOLD_SUSPICIOUS=0.4            # Risk score 0.4-0.7 = SUSPICIOUS
readonly ML_RANDOM_FOREST_ESTIMATORS=100             # Number of trees in Random Forest
readonly ML_ISOLATION_FOREST_CONTAMINATION=0.1       # Expected anomaly rate for Isolation Forest

# Standard filenames for ML artifacts
readonly ML_MODEL_FILE="ml_admission_controller_ident.pkl"    # Serialized ML models
readonly ML_DATABASE_FILE="ml_admission_controller_ident.db"  # SQLite database for results
readonly BASELINE_DATA_FILE="baseline.json"                   # Collected baseline Falco events
readonly FEATURE_NAMES_FILE="feature_names.json"              # List of 43 feature names
