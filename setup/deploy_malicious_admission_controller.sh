#!/bin/bash

# Deploy Malicious Admission Controller with TLS certificates (like baseline)
# Uses config/malicious_webhook.py and follows baseline deployment pattern

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NAMESPACE="monitoring-system"
ACTION="${1:-deploy}"
DURATION="${2:-600}"

# Load utilities
if [ -f "$PROJECT_DIR/lib/utils.sh" ]; then
    source "$PROJECT_DIR/lib/utils.sh"
fi

generate_certificates() {
    local service_name="$1"
    local namespace="$2"
    
    echo "Generating TLS certificates for $service_name in $namespace..."
    
    # Create certs directory
    mkdir -p "$PROJECT_DIR/certs"
    
    # Generate CA certificate if it doesn't exist
    if [ ! -f "$PROJECT_DIR/certs/ca.crt" ]; then
        openssl genrsa -out "$PROJECT_DIR/certs/ca.key" 2048
        openssl req -new -x509 -days 365 \
            -key "$PROJECT_DIR/certs/ca.key" \
            -subj "/CN=malicious-webhook-ca" \
            -out "$PROJECT_DIR/certs/ca.crt"
    fi
    
    # Generate server certificate for this service
    local key_file="$PROJECT_DIR/certs/${service_name}.key"
    local crt_file="$PROJECT_DIR/certs/${service_name}.crt"
    local csr_file="$PROJECT_DIR/certs/${service_name}.csr"
    local conf_file="$PROJECT_DIR/certs/${service_name}.conf"
    
    openssl genrsa -out "$key_file" 2048
    
    # Create config file with proper SANs
    cat > "$conf_file" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${service_name}.${namespace}.svc

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${service_name}
DNS.2 = ${service_name}.${namespace}
DNS.3 = ${service_name}.${namespace}.svc
DNS.4 = ${service_name}.${namespace}.svc.cluster.local
EOF
    
    # Generate certificate signing request
    openssl req -new \
        -key "$key_file" \
        -out "$csr_file" \
        -config "$conf_file"
    
    # Sign the server certificate
    openssl x509 -req -in "$csr_file" \
        -CA "$PROJECT_DIR/certs/ca.crt" \
        -CAkey "$PROJECT_DIR/certs/ca.key" \
        -CAcreateserial \
        -out "$crt_file" \
        -days 365 \
        -extensions v3_req \
        -extfile "$conf_file"
    
    echo "Certificates generated for $service_name"
}

create_tls_secret() {
    local namespace="$1"
    local secret_name="$2"
    local service_name="$3"
    
    echo "Creating TLS secret $secret_name in namespace $namespace..."
    
    # Delete existing secret if it exists
    kubectl delete secret "$secret_name" -n "$namespace" --ignore-not-found=true
    
    # Create new TLS secret
    kubectl create secret tls "$secret_name" \
        --cert="$PROJECT_DIR/certs/${service_name}.crt" \
        --key="$PROJECT_DIR/certs/${service_name}.key" \
        -n "$namespace"
    
    echo "TLS secret $secret_name created successfully"
}

generate_malicious_activity() {
    echo "Generating malicious webhook activity for ${DURATION} seconds..."
    
    # Generate realistic malicious admission controller activity continuously
    echo "Generating continuous malicious admission controller activity..."

    # Create pods with different malicious scenarios
    webhook_scenarios=(
        # Malicious scenarios
        "malicious-1:nginx:alpine:monitoring-agent.io/collect=true"
        "malicious-2:nginx:alpine:monitoring-agent.io/exfiltrate=enabled"
        
        # Privilege escalation scenarios  
        "privilege-1:nginx:alpine:security.agent.io/escalate=true"
        "privilege-2:nginx:alpine:container.escape.io/enabled=true"
        
        # Data exfiltration scenarios
        "exfiltrate-1:nginx:alpine:data.collection.io/tier=sensitive"
        "exfiltrate-2:nginx:alpine:credential.harvest.io/enabled=true"
    )

    # Record start time (exactly like baseline)
    activity_start=$(date +%s)
    activity_duration=$DURATION
    iteration=1
    
    echo "Malicious activity will run for ${activity_duration} seconds"
    
    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - activity_start))
        
        # Check if we've reached the duration (exactly like baseline)
        if [ $elapsed -ge $activity_duration ]; then
            echo "Malicious activity completed after ${elapsed} seconds"
            break
        fi
        
        # Select random webhook scenario (exactly like baseline)
        scenario_index=$((iteration % ${#webhook_scenarios[@]}))
        scenario=${webhook_scenarios[$scenario_index]}
        
        IFS=':' read -r pod_name image_name image_tag annotations <<< "$scenario"
        
        echo "Creating malicious test pod: ${pod_name}-${iteration} (${elapsed}s elapsed)"
        
        # Create pod with webhook annotations and malicious configurations (exactly like baseline structure)
        cat <<EOF | kubectl apply -f - >/dev/null 2>&1 || true
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}-${iteration}
  namespace: $NAMESPACE
  labels:
    test: malicious-webhook
    iteration: "$iteration"
    scenario: "${pod_name}"
    activity-phase: "continuous"
  annotations:
    webhook.test/scenario: "${pod_name}"
    malicious.agent.io/created-at: "$(date -Iseconds)"
    malicious.agent.io/elapsed: "${elapsed}s"
spec:
  containers:
  - name: app
    image: ${image_name}:${image_tag}
    ports:
    - containerPort: 80
    command: ["/bin/sh"]
    args: ["-c", "apk add --no-cache curl wget netcat-openbsd && while true; do echo 'Malicious activity at $(date)'; curl -s http://httpbin.org/ip || true; sleep 30; done"]
    env:
    - name: MALICIOUS_TEST
      value: "malicious-activity"
    - name: ITERATION
      value: "$iteration"
    securityContext:
      allowPrivilegeEscalation: true
      runAsNonRoot: false
      capabilities:
        add: ["NET_ADMIN", "SYS_TIME"]
    resources:
      requests:
        memory: "32Mi"
        cpu: "50m"
      limits:
        memory: "128Mi"
        cpu: "200m"
    volumeMounts:
    - name: host-proc
      mountPath: /host/proc
      readOnly: true
    - name: tmp-volume
      mountPath: /tmp
  volumes:
  - name: host-proc
    hostPath:
      path: /proc
  - name: tmp-volume
    emptyDir: {}
  restartPolicy: Never
  hostNetwork: false
  hostPID: false
  dnsPolicy: ClusterFirst
EOF
        
        # Wait for webhook processing (exactly like baseline)
        sleep 6
        
        # Test webhook endpoints and generate security activity (exactly like baseline pattern)
        echo "  → Testing webhook endpoints and generating malicious events..."
        webhook_services=("monitoring-agent")
        for service in "${webhook_services[@]}"; do
            echo "    - Testing $service"
            # Wait for pod to be ready
            kubectl wait --for=condition=Ready pod/${pod_name}-${iteration} -n "$NAMESPACE" --timeout=30s >/dev/null 2>&1 || true
            
            # Generate malicious events through various activities
            kubectl exec -n "$NAMESPACE" ${pod_name}-${iteration} -- sh -c "
                # Network activity
                wget -q --spider --timeout=2 http://${service}.${NAMESPACE}.svc.cluster.local:443/ || true
                
                # File system activity
                touch /tmp/malicious-${iteration}.log
                echo 'malicious webhook activity' > /tmp/malicious-${iteration}.log
                
                # Process activity
                ps aux > /tmp/process-list-${iteration}.txt || true
                
                # Network tools usage
                netstat -an > /tmp/network-${iteration}.txt 2>/dev/null || true
                
                # Capability testing
                ping -c 1 8.8.8.8 >/dev/null 2>&1 || true
            " 2>/dev/null || true
        done
        
        sleep 3
        
        # Clean up test pod (exactly like baseline)
        echo "  → Cleaning up ${pod_name}-${iteration}"
        kubectl delete pod ${pod_name}-${iteration} -n "$NAMESPACE" --ignore-not-found=true >/dev/null 2>&1 || true
        
        # Brief pause before next iteration (exactly like baseline)
        sleep 5
        
        iteration=$((iteration + 1))
        
        # Show progress every 30 seconds (exactly like baseline)
        if [ $((elapsed % 30)) -eq 0 ] && [ $elapsed -gt 0 ]; then
            remaining=$((activity_duration - elapsed))
            echo ""
            echo "PROGRESS: ${elapsed}s elapsed, ${remaining}s remaining (iteration $iteration)"
            echo "             Activity: $(echo "scale=1; $elapsed/60" | bc 2>/dev/null || echo $((elapsed/60)))min / $(echo "scale=1; $activity_duration/60" | bc 2>/dev/null || echo $((activity_duration/60)))min"
            echo ""
        fi
    done
}

echo "=== SOPHISTICATED MALICIOUS CONTROLLER DEPLOYMENT FOR ML TRAINING ==="
echo "Duration: ${DURATION} seconds" 
echo "Output: test-results/activity_training_[timestamp].json"
echo "Controller: monitoring-agent (sophisticated multi-stage attack)"
echo ""

if [ "$ACTION" = "deploy" ]; then
    echo "Deploying malicious admission controller..."
    
    # Create output directory and timestamp before deployment
    mkdir -p "$PROJECT_DIR/test-results"
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    OUTPUT_FILE="$PROJECT_DIR/test-results/activity_training_${TIMESTAMP}.json"
    
    echo "Output file: $OUTPUT_FILE"
    echo ""
    
    # Clean up any existing deployment
    echo "Cleaning up existing malicious controller deployment..."
    kubectl delete mutatingwebhookconfiguration monitoring-agent --ignore-not-found=true
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
    
    # Wait for namespace cleanup
    while kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; do
        echo "Waiting for namespace cleanup..."
        sleep 5
    done
    echo "Cleanup completed"
    
    # Create namespace
    kubectl create namespace "$NAMESPACE"
    
    # Generate certificates and TLS secret (like baseline)
    generate_certificates "monitoring-agent" "$NAMESPACE"
    create_tls_secret "$NAMESPACE" "monitoring-agent-certs" "monitoring-agent"
    
    # Create ConfigMap with malicious webhook code (like baseline)
    echo "Creating malicious webhook server configuration..."
    kubectl create configmap monitoring-agent-code \
        --from-file=malicious_webhook.py="$PROJECT_DIR/config/malicious_webhook.py" \
        -n "$NAMESPACE"
    
    # Deploy monitoring-agent webhook server (like baseline deployment pattern)
    echo "Deploying monitoring-agent server..."
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: monitoring-agent
  namespace: $NAMESPACE
  labels:
    app: monitoring-agent
    type: malicious-controller
spec:
  replicas: 1
  selector:
    matchLabels:
      app: monitoring-agent
  template:
    metadata:
      labels:
        app: monitoring-agent
        type: malicious-controller
    spec:
      containers:
      - name: webhook
        image: python:3.9-alpine
        command: ["/bin/sh"]
        args: ["-c", "python3 /app/malicious_webhook.py"]
        ports:
        - containerPort: 8443
        env:
        - name: WEBHOOK_TYPE
          value: "monitoring-agent"
        - name: PYTHONUNBUFFERED
          value: "1"
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          runAsGroup: 1000
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        volumeMounts:
        - name: monitoring-agent-certs
          mountPath: /etc/certs
          readOnly: true
        - name: monitoring-agent-config
          mountPath: /app
          readOnly: true
      volumes:
      - name: monitoring-agent-certs
        secret:
          secretName: monitoring-agent-certs
      - name: monitoring-agent-config
        configMap:
          name: monitoring-agent-code
          defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: monitoring-agent
  namespace: $NAMESPACE
spec:
  selector:
    app: monitoring-agent
  ports:
  - port: 443
    targetPort: 8443
EOF
    
    # Wait for deployment to be ready
    echo "Waiting for monitoring-agent to be ready..."
    kubectl wait --for=condition=available deployment/monitoring-agent -n "$NAMESPACE" --timeout=120s
    
    # Register the mutating webhook (like baseline)
    echo "Registering MutatingWebhookConfiguration..."
    cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: monitoring-agent
webhooks:
- name: monitoring-agent.monitoring-system.io
  clientConfig:
    service:
      name: monitoring-agent
      namespace: $NAMESPACE
      path: "/mutate"
    caBundle: $(base64 -w 0 < "$PROJECT_DIR/certs/ca.crt")
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
  namespaceSelector:
    matchExpressions:
    - key: name
      operator: NotIn
      values: ["kube-system", "falco", "kube-public", "kube-node-lease"]
EOF
    
    # Now start activity generation and Falco collection (like baseline does)
    echo "Starting malicious activity generation and data collection..."
    echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
    
    # Start Falco log collection in background (like baseline)
    timeout "${DURATION}s" kubectl logs -n falco -l app.kubernetes.io/name=falco -f --since=0s > "$OUTPUT_FILE" &
    FALCO_PID=$!
    
    # Generate malicious activity (like baseline generate_baseline_activity)
    generate_malicious_activity &
    ACTIVITY_PID=$!
    
    # Wait for activity generation to complete
    wait $ACTIVITY_PID
    echo "Malicious activity generation completed"
    
    # Wait for Falco collection to complete
    wait $FALCO_PID 2>/dev/null || true
    echo "Falco log collection completed"
    
    echo ""
    echo "Sophisticated malicious controller deployment completed!"
    echo "   Controller: monitoring-agent"
    echo "   Namespace: monitoring-system"
    echo "   Features: Multi-stage attack simulation, privilege escalation, data exfiltration"
    
    # Check if we got any events
    EVENT_COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo "0")
    
    echo ""
    echo "Data collection completed: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Events collected: $EVENT_COUNT"
    echo "Output saved to: $OUTPUT_FILE"
    echo ""
    echo "Next steps:"
    echo "  ./main.sh train    # Train ML models on this malicious data"
    
elif [ "$ACTION" = "cleanup" ]; then
    echo "Cleaning up malicious admission controller..."
    
    # Delete webhook configuration first
    echo "Deleting MutatingWebhookConfiguration..."
    kubectl delete mutatingwebhookconfiguration monitoring-agent --ignore-not-found=true || true
    
    # Delete namespace and all resources in it
    echo "Deleting namespace and all resources..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true || true
    
    # Wait for namespace cleanup
    while kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; do
        echo "Waiting for namespace cleanup..."
        sleep 2
    done
    
    # Clean up any remaining workload pods in other namespaces
    echo "Cleaning up any remaining malicious test pods..."
    kubectl delete pods -l malicious-test=true --all-namespaces --ignore-not-found=true || true
    
    # Clean up certificates
    echo "Cleaning up certificates..."
    rm -f "$PROJECT_DIR/certs/monitoring-agent"* || true
    
    echo ""
    echo "Cleanup completed!"
    echo "   ✓ Deleted MutatingWebhookConfiguration: monitoring-agent"
    echo "   ✓ Deleted namespace: $NAMESPACE (with all deployments, services, configmaps, secrets)"
    echo "   ✓ Cleaned up malicious test pods"
    echo "   ✓ Removed TLS certificates"
    
else
    echo "Usage: $0 [deploy|cleanup] [duration_in_seconds]"
    echo ""
    echo "Examples:"
    echo "  $0 deploy 600    # Deploy for 10 minutes"  
    echo "  $0 cleanup       # Clean up resources"
    exit 1
fi