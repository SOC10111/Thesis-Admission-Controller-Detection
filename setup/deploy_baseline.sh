#!/bin/bash

# Deploy Baseline Admission Controllers and Collect ML Training Data
# Consolidated script that handles both environment deployment and Falco log collection
#
# This script deploys 4 baseline admission controllers to generate normal behavior
# patterns for ML training:
# 1. cert-manager-webhook - Injects TLS certificates into pods
# 2. istio-sidecar-injector - Adds service mesh sidecar containers
# 3. resource-quota-webhook - Enforces resource limits
# 4. security-policy-validator - Validates security policies
#
# The script collects Falco events for 10 minutes while these controllers process
# pod creation requests, providing labeled training data for the ML models.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NAMESPACE="baseline-test"

echo "=== BASELINE DEPLOYMENT FOR ML TRAINING ==="
echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Duration: 10 minutes (600 seconds)"
echo "Output: test-results/baseline.json"
echo ""

# Create output directory
mkdir -p "$PROJECT_DIR/test-results"

# Load utilities
if [ -f "$PROJECT_DIR/lib/utils.sh" ]; then
    source "$PROJECT_DIR/lib/utils.sh"
fi

# Generate TLS certificates for webhook HTTPS endpoints
# Admission controllers require TLS for secure communication with the API server
generate_certificates() {
    local service_name="$1"  # The webhook service name
    local namespace="$2"     # Kubernetes namespace for the service
    
    # Create directory to store generated certificates
    mkdir -p "$PROJECT_DIR/certs"
    
    # Create a Certificate Authority (CA) if one doesn't exist
    # This CA will sign all webhook certificates
    if [ ! -f "$PROJECT_DIR/certs/ca.crt" ]; then
        openssl genrsa -out "$PROJECT_DIR/certs/ca.key" 2048
        openssl req -new -x509 -days 365 \
            -key "$PROJECT_DIR/certs/ca.key" \
            -subj "/CN=baseline-webhook-ca" \
            -out "$PROJECT_DIR/certs/ca.crt"
    fi
    
    # Generate server certificate for this service
    local key_file="$PROJECT_DIR/certs/${service_name}.key"
    local crt_file="$PROJECT_DIR/certs/${service_name}.crt"
    local csr_file="$PROJECT_DIR/certs/${service_name}.csr"
    local conf_file="$PROJECT_DIR/certs/${service_name}.conf"
    
    openssl genrsa -out "$key_file" 2048
    
    # Create OpenSSL config with Subject Alternative Names (SANs)
    # Required for the webhook to be accessible via various DNS names
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

# Create Kubernetes secret containing TLS certificates for webhook
create_tls_secret() {
    local namespace="$1"      # Target namespace for the secret
    local secret_name="$2"    # Name of the Kubernetes secret
    local service_name="$3"   # Service name (used to find cert files)
    
    # Remove any existing secret with the same name
    kubectl delete secret "$secret_name" -n "$namespace" --ignore-not-found=true
    
    # Create new TLS secret
    kubectl create secret tls "$secret_name" \
        --cert="$PROJECT_DIR/certs/${service_name}.crt" \
        --key="$PROJECT_DIR/certs/${service_name}.key" \
        -n "$namespace"
    
    echo "TLS secret $secret_name created successfully"
}

check_falco_connectivity() {
    echo "Checking Falco connectivity..."
    
    # Check if Falco pod exists and is running
    if ! kubectl get pods -n falco -l app.kubernetes.io/name=falco --field-selector=status.phase=Running >/dev/null 2>&1; then
        echo "ERROR: Falco not found or not running. Please install Falco first."
        echo "Install with: kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/kubernetes/falco.yaml"
        exit 1
    fi
    
    # Test Falco log output
    echo "Testing Falco log output..."
    if timeout 10s kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=5 | grep -q "Falco initialized"; then
        echo "Falco is generating logs successfully"
    else
        echo "WARNING: Falco may not be generating logs properly"
    fi
    
    echo "Falco connectivity verified"
}

deploy_baseline_environment() {
    echo "Deploying baseline environment..."
    echo "Deploying Simplified Baseline Environment for ML Training"
    echo "=========================================================="

    # Create namespace with webhook labels
    echo "Creating namespace: $NAMESPACE"
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    kubectl label namespace "$NAMESPACE" admission-webhook=enabled istio-injection=enabled --overwrite

    # Check Falco before proceeding
    check_falco_connectivity

    # Generate certificates and secrets for admission controllers
    generate_certificates "cert-manager-webhook" "$NAMESPACE"
    create_tls_secret "$NAMESPACE" "cert-manager-webhook-certs" "cert-manager-webhook"

    generate_certificates "istio-sidecar-injector" "$NAMESPACE" 
    create_tls_secret "$NAMESPACE" "istio-sidecar-injector-certs" "istio-sidecar-injector"

    generate_certificates "resource-quota-webhook" "$NAMESPACE"
    create_tls_secret "$NAMESPACE" "resource-quota-webhook-certs" "resource-quota-webhook"
    
    generate_certificates "security-policy-validator" "$NAMESPACE"
    create_tls_secret "$NAMESPACE" "security-policy-validator-certs" "security-policy-validator"

    # Create ConfigMaps with webhook server code
    echo "Creating webhook server configurations..."
    kubectl create configmap cert-manager-webhook-config \
      --from-file=cert-manager-webhook.py="$PROJECT_DIR/config/cert-manager-webhook.py" \
      -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    kubectl create configmap istio-sidecar-injector-config \
      --from-file=istio-sidecar-injector.py="$PROJECT_DIR/config/istio-sidecar-injector.py" \
      -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    kubectl create configmap resource-quota-webhook-config \
      --from-file=resource-quota-webhook.py="$PROJECT_DIR/config/resource-quota-webhook.py" \
      -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
      
    kubectl create configmap security-policy-validator-config \
      --from-file=security-policy-validator.py="$PROJECT_DIR/config/security-policy-validator.py" \
      -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # 1. Deploy cert-manager webhook controller
    echo "Deploying Container 1: Cert-Manager Webhook Controller"
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-webhook
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cert-manager-webhook
  template:
    metadata:
      labels:
        app: cert-manager-webhook
    spec:
      containers:
      - name: controller
        image: python:3.9-alpine
        command: ["/bin/sh"]
        args: ["-c", "python3 /app/cert-manager-webhook.py"]
        ports:
        - containerPort: 8443
        env:
        - name: WEBHOOK_TYPE
          value: "cert-manager"
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
        - name: webhook-certs
          mountPath: /etc/certs
          readOnly: true
        - name: webhook-config
          mountPath: /app
          readOnly: true
      volumes:
      - name: webhook-certs
        secret:
          secretName: cert-manager-webhook-certs
      - name: webhook-config
        configMap:
          name: cert-manager-webhook-config
          defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: cert-manager-webhook
  namespace: $NAMESPACE
spec:
  selector:
    app: cert-manager-webhook
  ports:
  - port: 443
    targetPort: 8443
EOF

    # 2. Deploy istio sidecar injector
    echo "Deploying Container 2: Istio Sidecar Injector"
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: istio-sidecar-injector
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: istio-sidecar-injector
  template:
    metadata:
      labels:
        app: istio-sidecar-injector
    spec:
      containers:
      - name: controller
        image: python:3.9-alpine
        command: ["/bin/sh"]
        args: ["-c", "python3 /app/istio-sidecar-injector.py"]
        ports:
        - containerPort: 8443
        env:
        - name: WEBHOOK_TYPE
          value: "sidecar-injector"
        - name: ISTIO_INJECTION
          value: "enabled"
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
        - name: webhook-certs
          mountPath: /etc/certs
          readOnly: true
        - name: webhook-config
          mountPath: /app
          readOnly: true
      volumes:
      - name: webhook-certs
        secret:
          secretName: istio-sidecar-injector-certs
      - name: webhook-config
        configMap:
          name: istio-sidecar-injector-config
          defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: istio-sidecar-injector
  namespace: $NAMESPACE
spec:
  selector:
    app: istio-sidecar-injector
  ports:
  - port: 443
    targetPort: 8443
EOF

    # 3. Deploy resource quota webhook
    echo "Deploying Container 3: Resource Quota Webhook"
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: resource-quota-webhook
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: resource-quota-webhook
  template:
    metadata:
      labels:
        app: resource-quota-webhook
    spec:
      containers:
      - name: controller
        image: python:3.9-alpine
        command: ["/bin/sh"]
        args: ["-c", "python3 /app/resource-quota-webhook.py"]
        ports:
        - containerPort: 8443
        env:
        - name: WEBHOOK_TYPE
          value: "resource-quota"
        - name: QUOTA_ENFORCEMENT
          value: "enabled"
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
        - name: webhook-certs
          mountPath: /etc/certs
          readOnly: true
        - name: webhook-config
          mountPath: /app
          readOnly: true
      volumes:
      - name: webhook-certs
        secret:
          secretName: resource-quota-webhook-certs
      - name: webhook-config
        configMap:
          name: resource-quota-webhook-config
          defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: resource-quota-webhook
  namespace: $NAMESPACE
spec:
  selector:
    app: resource-quota-webhook
  ports:
  - port: 443
    targetPort: 8443
EOF

    # 4. Deploy security policy validator
    echo "Deploying Container 4: Security Policy Validator (Validating)"
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-policy-validator
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-policy-validator
  template:
    metadata:
      labels:
        app: security-policy-validator
    spec:
      containers:
      - name: validator
        image: python:3.9-alpine
        command: ["/bin/sh"]
        args: ["-c", "python3 /app/security-policy-validator.py"]
        ports:
        - containerPort: 8443
        env:
        - name: WEBHOOK_TYPE
          value: "security-validator"
        - name: VALIDATION_MODE
          value: "strict"
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
        - name: webhook-certs
          mountPath: /etc/certs
          readOnly: true
        - name: webhook-config
          mountPath: /app
          readOnly: true
      volumes:
      - name: webhook-certs
        secret:
          secretName: security-policy-validator-certs
      - name: webhook-config
        configMap:
          name: security-policy-validator-config
          defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: security-policy-validator
  namespace: $NAMESPACE
spec:
  selector:
    app: security-policy-validator
  ports:
  - port: 443
    targetPort: 8443
---
# Register the mutating webhooks with Kubernetes admission system
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: baseline-webhook-config
webhooks:
- name: cert-manager.baseline.io
  clientConfig:
    service:
      name: cert-manager-webhook
      namespace: $NAMESPACE
      path: "/mutate"
    caBundle: $(base64 -w 0 < "$PROJECT_DIR/certs/ca.crt")
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods", "secrets", "configmaps"]
  namespaceSelector:
    matchLabels:
      admission-webhook: "enabled"
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
- name: istio-sidecar.baseline.io
  clientConfig:
    service:
      name: istio-sidecar-injector
      namespace: $NAMESPACE
      path: "/mutate"
    caBundle: $(base64 -w 0 < "$PROJECT_DIR/certs/ca.crt")
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  namespaceSelector:
    matchLabels:
      istio-injection: "enabled"
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
- name: resource-quota.baseline.io
  clientConfig:
    service:
      name: resource-quota-webhook
      namespace: $NAMESPACE
      path: "/validate"
    caBundle: $(base64 -w 0 < "$PROJECT_DIR/certs/ca.crt")
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods", "deployments"]
  namespaceSelector: {}
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
EOF

    # Register the validating webhook with Kubernetes admission system
    echo "Registering Security Policy Validator as ValidatingWebhookConfiguration..."
    cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: security-policy-validator-config
webhooks:
- name: security-policy.baseline.io
  clientConfig:
    service:
      name: security-policy-validator
      namespace: $NAMESPACE
      path: "/validate"
    caBundle: $(base64 -w 0 < "$PROJECT_DIR/certs/ca.crt")
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["", "apps"]
    apiVersions: ["v1"]
    resources: ["pods", "deployments", "replicasets"]
  namespaceSelector:
    matchLabels:
      admission-webhook: "enabled"
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
EOF

    # 5-6. Deploy 2 regular application containers
    for i in {5..6}; do
      echo "Deploying Container $i: Regular Application"
      cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: regular-app-$i
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: regular-app-$i
  template:
    metadata:
      labels:
        app: regular-app-$i
    spec:
      containers:
      - name: app
        image: nginx:alpine
        ports:
        - containerPort: 80
        env:
        - name: APP_TYPE
          value: "regular"
        resources:
          requests:
            memory: "32Mi"
            cpu: "25m"
          limits:
            memory: "64Mi"
            cpu: "50m"
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
EOF
    done

    # 7. Deploy simple sidecar container for webhook testing
    echo "Deploying Container 7: Test Application with Sidecar"
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app-sidecar
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-app-sidecar
  template:
    metadata:
      labels:
        app: test-app-sidecar
    spec:
      containers:
      - name: main
        image: nginx:alpine
        ports:
        - containerPort: 80
        env:
        - name: CONTAINER_TYPE
          value: "test-sidecar"
        resources:
          requests:
            memory: "32Mi"
            cpu: "25m"
          limits:
            memory: "64Mi"
            cpu: "50m"
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
      - name: sidecar
        image: busybox:latest
        command: ['sh', '-c', 'while true; do echo "$(date): sidecar active"; sleep 30; done']
        resources:
          requests:
            memory: "16Mi"
            cpu: "10m"
          limits:
            memory: "32Mi"
            cpu: "20m"
EOF

    # Wait for all deployments to be ready with better timeout handling
    echo "Waiting for all containers to be ready..."
    if ! kubectl wait --for=condition=available --timeout=120s deployment --all -n "$NAMESPACE"; then
        echo "WARNING: Some deployments may not be ready yet. Checking status..."
        kubectl get deployments -n "$NAMESPACE"
    fi

    # Test Falco log generation after deployment
    echo "Testing Falco log generation with new deployments..."
    sleep 5
    if timeout 15s kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -q "$NAMESPACE"; then
        echo "Falco is detecting activity from baseline environment"
    else
        echo "WARNING: Falco may not be detecting baseline activity yet"
    fi

    # Display deployment status
    echo ""
    echo "Baseline Environment Status:"
    echo "============================="
    kubectl get deployments,pods,services -n "$NAMESPACE"

    echo ""
    echo "Simplified baseline environment deployed successfully!"
    echo "Environment contains:"
    echo "   - 4 Admission Controllers (cert-manager, istio-sidecar, resource-quota, security-validator)"
    echo "   - 2 Regular application containers"  
    echo "   - 1 Test application with sidecar"
    echo "   - Total: 7 containers (including validating admission controller)"
}

generate_baseline_activity() {
    echo "Generating baseline webhook activity for 10 minutes..."
    
    # Generate realistic admission controller activity continuously for 600 seconds
    echo "Generating continuous admission controller activity..."

    # Create pods with different webhook triggers
    webhook_scenarios=(
        # Cert-manager scenarios
        "cert-test-1:nginx:alpine:cert-manager.io/issuer=ca-issuer"
        "cert-test-2:nginx:alpine:cert-manager.io/certificate-name=test-cert"
        
        # Istio sidecar scenarios  
        "istio-test-1:nginx:alpine:istio-injection=enabled"
        "istio-test-2:nginx:alpine:sidecar.istio.io/inject=true"
        
        # Resource quota scenarios
        "quota-test-1:nginx:alpine:resource-quota.io/tier=standard"
        "quota-test-2:nginx:alpine:resource-quota.io/enforce=true"
    )

    # Record start time
    activity_start=$(date +%s)
    activity_duration=600  # 10 minutes
    iteration=1
    
    echo "Baseline activity will run for ${activity_duration} seconds (10 minutes)"
    
    while true; do
        current_time=$(date +%s)
        elapsed=$((current_time - activity_start))
        
        # Check if we've reached the duration
        if [ $elapsed -ge $activity_duration ]; then
            echo "Baseline activity completed after ${elapsed} seconds"
            break
        fi
        
        # Select random webhook scenario
        scenario_index=$((iteration % ${#webhook_scenarios[@]}))
        scenario=${webhook_scenarios[$scenario_index]}
        
        IFS=':' read -r pod_name image_name image_tag annotations <<< "$scenario"
        
        echo "Creating webhook test pod: ${pod_name}-${iteration} (${elapsed}s elapsed)"
        
        # Create pod with webhook annotations and security-triggering configurations
        cat <<EOF | kubectl apply -f - >/dev/null 2>&1 || true
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}-${iteration}
  namespace: $NAMESPACE
  labels:
    test: baseline-webhook
    iteration: "$iteration"
    scenario: "${pod_name}"
    activity-phase: "continuous"
  annotations:
    webhook.test/scenario: "${pod_name}"
    activity.baseline.io/created-at: "$(date -Iseconds)"
    activity.baseline.io/elapsed: "${elapsed}s"
spec:
  containers:
  - name: app
    image: ${image_name}:${image_tag}
    ports:
    - containerPort: 80
    command: ["/bin/sh"]
    args: ["-c", "apk add --no-cache curl wget netcat-openbsd && while true; do echo 'Activity at $(date)'; curl -s http://httpbin.org/ip || true; sleep 30; done"]
    env:
    - name: WEBHOOK_TEST
      value: "baseline-activity"
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
        
        # Wait for webhook processing (reduced to keep activity more frequent)
        sleep 6
        
        # Test webhook endpoints and generate security activity
        echo "  → Testing webhook endpoints and generating security events..."
        webhook_services=("cert-manager-webhook" "istio-sidecar-injector" "resource-quota-webhook" "security-policy-validator")
        for service in "${webhook_services[@]}"; do
            echo "    - Testing $service"
            # Wait for pod to be ready
            kubectl wait --for=condition=Ready pod/${pod_name}-${iteration} -n "$NAMESPACE" --timeout=30s >/dev/null 2>&1 || true
            
            # Generate security events through various activities
            kubectl exec -n "$NAMESPACE" ${pod_name}-${iteration} -- sh -c "
                # Network activity
                wget -q --spider --timeout=2 http://${service}.${NAMESPACE}.svc.cluster.local:443/ || true
                
                # File system activity
                touch /tmp/webhook-test-${iteration}.log
                echo 'webhook test activity' > /tmp/webhook-test-${iteration}.log
                
                # Process activity
                ps aux > /tmp/process-list-${iteration}.txt || true
                
                # Network tools usage
                netstat -an > /tmp/network-${iteration}.txt 2>/dev/null || true
                
                # Capability testing
                ping -c 1 8.8.8.8 >/dev/null 2>&1 || true
            " 2>/dev/null || true
        done
        
        sleep 3
        
        # Clean up test pod
        echo "  → Cleaning up ${pod_name}-${iteration}"
        kubectl delete pod ${pod_name}-${iteration} -n "$NAMESPACE" --ignore-not-found=true >/dev/null 2>&1 || true
        
        # Brief pause before next iteration
        sleep 5
        
        iteration=$((iteration + 1))
        
        # Show progress every 30 seconds
        if [ $((elapsed % 30)) -eq 0 ] && [ $elapsed -gt 0 ]; then
            remaining=$((activity_duration - elapsed))
            echo ""
            echo "PROGRESS: ${elapsed}s elapsed, ${remaining}s remaining (iteration $iteration)"
            echo "             Activity: $(echo "scale=1; $elapsed/60" | bc 2>/dev/null || echo $((elapsed/60)))min / 10min"
            echo ""
        fi
    done
}

# Main execution starts here
echo "Falco verified - ready to collect logs"

# Deploy baseline environment
deploy_baseline_environment

echo ""
echo "Starting comprehensive data collection..."
echo "Data collection started: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Expected completion: $(date -d '+10 minutes' '+%Y-%m-%d %H:%M:%S')"
echo "Fresh 10-minute collection from current session"

# Start workload generation in background
generate_baseline_activity &
WORKLOAD_PID=$!

# Start fresh Falco log collection from current session only
echo "Starting fresh Falco log collection from current session..."
timeout 600s kubectl logs -n falco -l app.kubernetes.io/name=falco -f --since=0s > "$PROJECT_DIR/test-results/baseline.json" &
FALCO_PID=$!

echo "Data collection in progress... (10 minutes)"

# Wait for workload generation to complete first (shorter duration)
wait $WORKLOAD_PID
echo "Baseline activity generation completed"

# Continue Falco data collection for full 10 minutes
echo "⏳ Continuing Falco data collection..."
wait $FALCO_PID
echo "Falco log collection completed: $(date '+%Y-%m-%d %H:%M:%S')"

# Verify baseline.json was created successfully
if [ ! -f "$PROJECT_DIR/test-results/baseline.json" ] || [ ! -s "$PROJECT_DIR/test-results/baseline.json" ]; then
    echo "ERROR: Failed to collect baseline Falco logs"
    exit 1
fi

echo ""
echo "BASELINE DEPLOYMENT COMPLETED SUCCESSFULLY!"
echo "Completed: $(date '+%Y-%m-%d %H:%M:%S')"

# Count total events and admission controller events
total_events=$(wc -l < "$PROJECT_DIR/test-results/baseline.json" 2>/dev/null || echo "0")
echo "Total Falco events collected: $total_events"

# Quick count of admission controller related events
admission_events=$(grep -c -i "webhook\|admission\|mutating\|validating" "$PROJECT_DIR/test-results/baseline.json" 2>/dev/null || echo "0")
echo "Admission controller related events: $admission_events"

echo "📁 Output file: test-results/baseline.json"
echo "Fresh 10-minute collection from current session"
echo ""
echo "Next steps:"
echo "  ./main.sh train-baseline    # Train ML models on this baseline data"