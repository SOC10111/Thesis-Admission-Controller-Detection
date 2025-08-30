#!/bin/bash
# =============================================================================
# COMPLETE CLEANUP: utils/cleanup.sh
# Comprehensive cleanup for Falco ML analysis project
# =============================================================================

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/utils.sh"
source "${SCRIPT_DIR}/../config/constants.sh"

cleanup_processes() {
    echo "Terminating background processes..."
    
    # Kill ML processes
    pkill -f "admission_controller_ml.py" 2>/dev/null || true
    
    # Kill workload generation processes
    pkill -f "comprehensive_malicious_activity.sh" 2>/dev/null || true
    
    
    # Clean up port conflicts
    for port in 5000 5001 8443; do
        if command -v lsof >/dev/null 2>&1; then
            lsof -ti:$port | xargs -r kill 2>/dev/null || true
        fi
    done
    
    # Clean up PID files
    find "${TEST_RESULTS_DIR}" -name "*.pid" -delete 2>/dev/null || true
}

cleanup_training_pods() {
    echo "Cleaning up test pods..."
    
    # Clean up by pattern matching (comprehensive cleanup) - current project patterns
    local patterns=("training-" "test-" "ml-test" "simple-" "webhook-test" "security-test" "apm-test" "webhook-trigger-" "escape-attempt-" "network-recon-" "persistent-attack")
    
    for pattern in "${patterns[@]}"; do
        kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep "$pattern" | while read namespace pod rest; do
            if [[ -n "$pod" && -n "$namespace" ]]; then
                kubectl delete pod "$pod" -n "$namespace" --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
            fi
        done
    done
    
    # Clean up pods in test namespaces
    local test_namespaces=("test-ml" "training-ns" "webhook-test")
    for ns in "${test_namespaces[@]}"; do
        if kubectl get namespace "$ns" >/dev/null 2>&1; then
            kubectl delete pods --all -n "$ns" --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
        fi
    done
    
    # Clean up by labels (current project actual labels)
    echo "Cleaning up pods by labels..."
    kubectl delete pods -l webhook-trigger=true --all-namespaces --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    kubectl delete pods -l malicious=true --all-namespaces --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    kubectl delete pods -l app=monitoring-agent --all-namespaces --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    kubectl delete pods -l test=webhook --all-namespaces --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    kubectl delete pods -l test=ml --all-namespaces --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    kubectl delete pods -l test=legitimate-webhook --all-namespaces --ignore-not-found=true --force --grace-period=0 2>/dev/null || true
    
    # Clean up completed/failed pods that match our patterns
    echo "Cleaning up completed/failed pods..."
    kubectl delete pods --all-namespaces --field-selector=status.phase=Succeeded --ignore-not-found=true 2>/dev/null | grep -E "(webhook-trigger-|escape-attempt-|network-recon-|persistent-attack)" || true
    kubectl delete pods --all-namespaces --field-selector=status.phase=Failed --ignore-not-found=true 2>/dev/null | grep -E "(webhook-trigger-|escape-attempt-|network-recon-|persistent-attack)" || true
    
    # Clean up malicious activity resources (ConfigMaps and Secrets)
    echo "Cleaning up malicious activity resources..."
    for ns in "monitoring-system" "baseline-test"; do
        if kubectl get namespace "$ns" >/dev/null 2>&1; then
            # Clean up malicious ConfigMaps and Secrets created by comprehensive_malicious_activity.sh
            kubectl delete configmaps -l app=malicious-data -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete secrets -l app=exfil-secret -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete configmap monitoring-config -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete secret monitoring-secret -n "$ns" --ignore-not-found=true 2>/dev/null || true
            
            # Clean up by name pattern (created by malicious scripts)
            for i in {1..10}; do
                kubectl delete configmap "malicious-data-$i" -n "$ns" --ignore-not-found=true 2>/dev/null || true
                kubectl delete secret "exfil-secret-$i" -n "$ns" --ignore-not-found=true 2>/dev/null || true
            done
        fi
    done
    
    # Wait for pods to be fully deleted
    sleep 3
}

cleanup_webhooks() {
    echo "Cleaning up webhook configurations..."
    
    # Webhook configurations (current project actual names)
    local webhook_configs=(
        "baseline-webhook-config"
        "monitoring-agent"
        "security-policy-enforcer"
        "apm-injector"
        "istio-sidecar-injector"
        "cert-manager-webhook"
        "malicious-webhook"
    )
    
    for config in "${webhook_configs[@]}"; do
        echo "Deleting webhook configuration: $config"
        kubectl delete mutatingwebhookconfiguration "$config" --ignore-not-found=true 2>/dev/null || true
    done
}

cleanup_deployments() {
    echo "Cleaning up deployments and services..."
    
    # Webhook deployments by namespace (current project actual deployments)
    local namespaces_deployments=(
        "baseline-test:cert-manager-webhook"
        "baseline-test:istio-sidecar-injector"
        "baseline-test:resource-quota-webhook"
        "baseline-test:security-policy-validator"
        "monitoring-system:monitoring-agent"
        "kube-security:security-policy-enforcer"
        "observability:apm-injector"
        "istio-system:istio-sidecar-injector"
        "cert-manager:cert-manager-webhook"
        "malicious-webhook:malicious-webhook"
    )
    
    for entry in "${namespaces_deployments[@]}"; do
        local ns="${entry%%:*}"
        local deployment="${entry##*:}"
        
        if kubectl get namespace "$ns" >/dev/null 2>&1; then
            kubectl delete deployment "$deployment" -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete service "$deployment" -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete service "${deployment}-svc" -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete service "${deployment}-service" -n "$ns" --ignore-not-found=true 2>/dev/null || true
            
            # Clean up related ConfigMaps and Secrets
            kubectl delete configmap "${deployment}-config" -n "$ns" --ignore-not-found=true 2>/dev/null || true
            kubectl delete secret "${deployment}-certs" -n "$ns" --ignore-not-found=true 2>/dev/null || true
        fi
    done
}

cleanup_namespaces() {
    echo "Cleaning up test namespaces..."
    
    # Project-specific test namespaces (current project actual namespaces)
    local test_namespaces=(
        "baseline-test"
        "monitoring-system"
        "production-baseline"
        "security"
        "monitoring"
        "webhook-test"
        "admission-test"
        "malicious-test"
        "training-ns"
        "test-ml"
    )
    
    for ns in "${test_namespaces[@]}"; do
        if kubectl get namespace "$ns" >/dev/null 2>&1; then
            kubectl delete namespace "$ns" --ignore-not-found=true --timeout=60s >/dev/null 2>&1 || true
        fi
    done
    
    # Do NOT delete Kubernetes system namespaces or Falco
    # - kube-system, kube-public, kube-node-lease (protected)
    # - falco (protected)
    # - cert-manager, istio-system (may be used by other systems)
}

cleanup_rbac() {
    echo "Cleaning up RBAC resources..."
    
    local cluster_roles=(
        "security-policy-enforcer"
        "apm-injector"
        "cert-manager-webhook"
        "malicious-webhook"
    )
    
    for role in "${cluster_roles[@]}"; do
        kubectl delete clusterrole "$role" --ignore-not-found=true 2>/dev/null || true
        kubectl delete clusterrolebinding "$role" --ignore-not-found=true 2>/dev/null || true
    done
}

cleanup_databases() {
    echo "Emptying ML databases (preserving structure)..."
    
    # Empty databases instead of deleting them
    if [[ -d "${TEST_RESULTS_DIR}" ]]; then
        # Find and empty SQLite databases
        find "${TEST_RESULTS_DIR}" -name "*.db" | while read db_file; do
            if [[ -f "$db_file" ]]; then
                echo "Emptying database: $(basename "$db_file")"
                # Get table names and clear them while preserving structure
                sqlite3 "$db_file" ".tables" 2>/dev/null | tr ' ' '\n' | while read table; do
                    if [[ -n "$table" ]]; then
                        sqlite3 "$db_file" "DELETE FROM $table;" 2>/dev/null || true
                    fi
                done
                echo "Database $(basename "$db_file") emptied (structure preserved)"
            fi
        done
    fi
}

cleanup_files() {
    echo "Cleaning up generated files..."
    
    # Handle test-results directory based on options
    if [[ "${KEEP_MODELS:-false}" != "true" ]]; then
        # Remove everything in test-results
        if [[ -d "${TEST_RESULTS_DIR}" ]]; then
            rm -rf "${TEST_RESULTS_DIR}"/* 2>/dev/null || true
        fi
    else
        # Keep model and DB files, remove others but empty databases
        if [[ -d "${TEST_RESULTS_DIR}" ]]; then
            find "${TEST_RESULTS_DIR}" -name "*.json" -not -name "feature_names*.json" -delete 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "*.txt" -delete 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "*.log" -delete 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "*.pid" -delete 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "baseline_*" -delete 2>/dev/null || true
            # Specifically remove baseline.json that may contain old monitoring-agent data
            rm -f "${TEST_RESULTS_DIR}/baseline.json" 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "activity_*" -delete 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "malicious_*" -delete 2>/dev/null || true
            find "${TEST_RESULTS_DIR}" -name "report_*" -delete 2>/dev/null || true
            # Keep: *.pkl, *.db (but empty databases), feature_names*.json
        fi
    fi
    
    # Always empty databases (preserving structure) regardless of keep-models option
    if [[ -d "${TEST_RESULTS_DIR}" ]]; then
        cleanup_databases
    fi
    
    # Clean up certificates and temporary configs
    rm -rf "${SCRIPT_DIR}/../certs/"* 2>/dev/null || true
    # Note: Keep essential webhook Python files - only remove temporary manifests
    rm -f "${SCRIPT_DIR}/../config/"*-webhook-manifest.yaml 2>/dev/null || true
    rm -f "${SCRIPT_DIR}/../config/"*-rbac.yaml 2>/dev/null || true
    rm -f "${SCRIPT_DIR}/../temp_header" 2>/dev/null || true
    
    # Clean up log files and temp files
    find /tmp -name "falco_*.log" -mtime +1 -delete 2>/dev/null || true
    find /tmp -name "cleanup.log" -mtime +7 -delete 2>/dev/null || true
}

verify_cleanup() {
    log_info "Verifying cleanup completion"
    
    # Check for remaining webhook configs
    local remaining_webhooks=0
    if kubectl get mutatingwebhookconfiguration --no-headers 2>/dev/null | grep -E "(baseline-webhook|monitoring-agent|security-policy|apm-injector|istio-sidecar|malicious)" >/dev/null 2>&1; then
        remaining_webhooks=$(kubectl get mutatingwebhookconfig --no-headers 2>/dev/null | grep -E "(baseline-webhook|monitoring-agent|security-policy|apm-injector|istio-sidecar|malicious)" | wc -l | tr -d ' \n' || echo "0")
    fi
    
    if [[ "$remaining_webhooks" -gt 0 ]]; then
        log_warn "Some webhook configurations still exist"
        kubectl get mutatingwebhookconfiguration --no-headers | grep -E "(baseline-webhook|monitoring-agent|security-policy|apm-injector|istio-sidecar|malicious)" || true
    else
        log_info "All webhook configurations removed"
    fi
    
    # Check for remaining test pods
    local remaining_pods=0
    if kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -E "(webhook-trigger-|escape-attempt-|network-recon-|persistent-attack|training-|ml-test-|webhook-test)" >/dev/null 2>&1; then
        remaining_pods=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -E "(webhook-trigger-|escape-attempt-|network-recon-|persistent-attack|training-|ml-test-|webhook-test)" | wc -l | tr -d ' \n' || echo "0")
    fi
    
    if [[ "$remaining_pods" -gt 0 ]]; then
        log_warn "Some test pods still exist"
        kubectl get pods --all-namespaces | grep -E "(webhook-trigger-|escape-attempt-|network-recon-|persistent-attack|training-|ml-test-|webhook-test)" || true
    else
        log_info "All test pods removed"
    fi
    
    # Check for processes on ports 5000, 5001
    if command -v lsof >/dev/null 2>&1; then
        for port in 5000 5001; do
            if lsof -ti:$port >/dev/null 2>&1; then
                log_warn "Port $port still in use"
            else
                log_info "Port $port is free"
            fi
        done
    fi
}

show_usage() {
    cat <<USAGE
Comprehensive Cleanup Script

Usage: $0 [OPTIONS]

Options:
    --keep-models    Keep trained ML models (only clean runtime files)
    --force          Force cleanup without confirmation
    --verify-only    Only verify current state, don't clean
    --help           Show this help

Examples:
    $0                    # Full cleanup with confirmation
    $0 --keep-models      # Clean but keep ML models  
    $0 --force            # Force cleanup without asking
    $0 --verify-only      # Check what needs cleaning

This script cleans up:
- Webhook configurations and deployments
- Training and test pods
- Test namespaces
- Running ML processes
- Temporary files and logs
- ML databases (emptied, structure preserved)
- ConfigMaps and Secrets from malicious activities
USAGE
}

main() {
    local keep_models=false
    local force=false
    local verify_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --keep-models)
                keep_models=true
                shift
                ;;
            --force)
                force=true
                shift
                ;;
            --verify-only)
                verify_only=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    export KEEP_MODELS="$keep_models"
    
    if [[ "$verify_only" == "true" ]]; then
        log_info "Verification mode - checking current state"
        verify_cleanup
        exit 0
    fi
    
    # Minimal output - only show progress when forced
    if [[ "$force" != "true" ]]; then
        echo "Cleanup will remove test resources, processes, and generated files."
        if [[ "$keep_models" == "true" ]]; then
            echo "ML models and database will be preserved."
        fi
        read -p "Continue? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Cleanup cancelled"
            exit 0
        fi
    fi
    
    echo "Starting cleanup..."
    
    # Execute cleanup in order with error handling
    echo "Starting comprehensive cleanup process..."
    
    cleanup_processes || log_warn "Some processes may still be running"
    cleanup_training_pods || log_warn "Some pods may still exist" 
    cleanup_webhooks || log_warn "Some webhook configurations may still exist"
    cleanup_deployments || log_warn "Some deployments may still exist"
    cleanup_rbac || log_warn "Some RBAC resources may still exist"
    cleanup_namespaces || log_warn "Some namespaces may still exist"
    cleanup_files || log_warn "Some files may still exist"
    
    echo "Cleanup process completed (check verification for any remaining resources)"
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
