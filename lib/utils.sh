#!/bin/bash
# Streamlined utilities for Falco ML project
# Contains only functions that are actually used
#
# This file provides shared utility functions used across all bash scripts:
# - Logging functions with timestamps and log levels
# - Kubernetes resource management helpers
# - System prerequisite validation

set -euo pipefail

# Prevent this file from being sourced multiple times
[[ -n "${UTILS_LOADED:-}" ]] && return 0
readonly UTILS_LOADED=1

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

# Set up logging configuration
readonly SCRIPT_NAME=${SCRIPT_NAME:-"$(basename "${BASH_SOURCE[0]}")"}
readonly LOG_FILE="${LOG_FILE:-/tmp/${SCRIPT_NAME%.*}.log}"

# Core logging function that writes to both console and log file
log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

# Convenience functions for different log levels
log_info() { log "INFO" "$@"; }        # General information messages
log_warn() { log "WARN" "$@"; }        # Warning messages (non-fatal issues)
log_error() { log "ERROR" "$@" >&2; }  # Error messages (sent to stderr)
log_debug() { [[ "${DEBUG:-}" == "true" ]] && log "DEBUG" "$@" || true; }  # Debug messages (only if DEBUG=true)

# Exit script with error message
die() {
    log_error "$@"
    exit 1
}

# =============================================================================
# KUBERNETES UTILITIES
# =============================================================================

# Delete a Kubernetes resource safely (ignores if it doesn't exist)
cleanup_resource() {
    local resource_type="$1"    # Type of resource (deployment, service, etc.)
    local resource_name="$2"    # Name of the resource
    local namespace="${3:-default}"  # Namespace (defaults to 'default')
    
    log_info "Cleaning up $resource_type/$resource_name in namespace $namespace"
    kubectl delete "$resource_type" "$resource_name" -n "$namespace" --ignore-not-found=true || {
        log_warn "Failed to delete $resource_type/$resource_name, continuing..."
    }
}

# Wait for a Kubernetes resource to reach a specific condition
wait_for_condition() {
    local condition="$1"     # Condition to wait for (e.g., "condition=ready")
    local resource="$2"      # Resource to check (e.g., "pod/my-pod")
    local namespace="$3"     # Namespace of the resource
    local timeout="${4:-120s}"  # Maximum wait time (default 2 minutes)
    
    log_info "Waiting for $condition on $resource in $namespace (timeout: $timeout)"
    
    # Handle both label selectors and specific resource names
    if [[ "$resource" == *"-l "* ]]; then
        # Resource is specified with a label selector
        kubectl wait --for="$condition" $resource -n "$namespace" --timeout="$timeout" || {
            die "Timeout waiting for $condition on $resource"
        }
    else
        # Resource is specified by name
        kubectl wait --for="$condition" "$resource" -n "$namespace" --timeout="$timeout" || {
            die "Timeout waiting for $condition on $resource"
        }
    fi
}

# Create a Kubernetes namespace if it doesn't already exist
ensure_namespace() {
    local namespace="$1"  # Name of the namespace to create
    
    if ! kubectl get namespace "$namespace" >/dev/null 2>&1; then
        log_info "Creating namespace $namespace"
        kubectl create namespace "$namespace"
    else
        log_info "Namespace $namespace already exists"
    fi
}

# =============================================================================
# SYSTEM VALIDATION
# =============================================================================

# Verify that all required tools are installed and the cluster is accessible
check_prerequisites() {
    # List of required command-line tools for the ML detection system
    local tools=("kubectl" "helm" "docker" "openssl")
    for tool in "${tools[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
    done
    
    # Verify connection to Kubernetes cluster
    kubectl cluster-info >/dev/null 2>&1 || die "Cannot connect to Kubernetes cluster"
    
    # Configure Docker to use Minikube's Docker daemon if running locally
    if [[ "${USE_MINIKUBE:-true}" == "true" ]]; then
        eval "$(minikube docker-env)" || die "Failed to configure minikube docker environment"
    fi
}

# Export all utility functions so they can be used by scripts that source this file
export -f log log_info log_warn log_error log_debug die
export -f cleanup_resource wait_for_condition ensure_namespace
export -f check_prerequisites