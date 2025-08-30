#!/usr/bin/env python3
"""
Istio Sidecar Injector Webhook Server
Simulates service mesh sidecar injection behavior
"""

import json
import logging
import time
import base64
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import ssl
import os

def setup_logging_and_ssl(cert_path='/etc/certs/tls.crt', key_path='/etc/certs/tls.key'):
    """Setup logging and SSL context for webhook server"""
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    # Create SSL context
    ssl_context = None
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)
        logger.info("Loaded TLS certificates")
    else:
        logger.warning("TLS certificates not found, running without SSL")
    
    return logger, ssl_context

def create_admission_response(uid, allowed=True, message="", patches=None):
    """Create standardized AdmissionReview response"""
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed
        }
    }
    
    if message:
        response["response"]["result"] = {"message": message}
    
    if patches and allowed:
        response["response"]["patchType"] = "JSONPatch"
        response["response"]["patch"] = base64.b64encode(json.dumps(patches).encode()).decode()
    
    return response

logger, _ = setup_logging_and_ssl()  # Initialize logger for module level

class IstioSidecarInjectorHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            admission_review = json.loads(post_data.decode('utf-8'))
            
            logger.info(f"Processing sidecar injection request: {self.path}")
            
            if self.path == '/inject':
                response = self.handle_inject(admission_review)
            elif self.path == '/validate':
                response = self.handle_validate(admission_review)
            else:
                response = self.create_error_response("Unknown endpoint")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error processing sidecar injection: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_inject(self, admission_review):
        """Handle sidecar injection into pods"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        
        logger.info(f"Injecting Istio sidecar into pod: {pod_name} in namespace: {namespace}")
        
        # Check if sidecar injection is needed
        annotations = pod.get('metadata', {}).get('annotations', {})
        labels = pod.get('metadata', {}).get('labels', {})
        
        should_inject = (
            annotations.get('istio-injection') == 'enabled' or
            annotations.get('sidecar.istio.io/inject') == 'true' or
            labels.get('istio-injection') == 'enabled'
        )
        
        patches = []
        
        if should_inject:
            # Add Istio proxy sidecar container
            sidecar_container = {
                "op": "add",
                "path": "/spec/containers/-",
                "value": {
                    "name": "istio-proxy",
                    "image": "istio/proxyv2:1.17.2",
                    "args": [
                        "proxy",
                        "sidecar",
                        "--domain",
                        f"{namespace}.svc.cluster.local",
                        "--serviceCluster",
                        f"{pod_name}.{namespace}",
                        "--proxyLogLevel=warning",
                        "--proxyComponentLogLevel=misc:error",
                        "--log_output_level=default:info"
                    ],
                    "ports": [
                        {"containerPort": 15090, "protocol": "TCP", "name": "http-envoy-prom"},
                        {"containerPort": 15001, "protocol": "TCP", "name": "http-envoy-admin"},
                        {"containerPort": 15006, "protocol": "TCP", "name": "http-envoy-inbound"}
                    ],
                    "env": [
                        {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                        {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
                        {"name": "INSTANCE_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}},
                        {"name": "SERVICE_ACCOUNT", "valueFrom": {"fieldRef": {"fieldPath": "spec.serviceAccountName"}}},
                        {"name": "ISTIO_META_POD_PORTS", "value": "[{\"containerPort\":80,\"protocol\":\"TCP\"}]"},
                        {"name": "ISTIO_META_APP_CONTAINERS", "value": "app"},
                        {"name": "ISTIO_META_CLUSTER_ID", "value": "Kubernetes"},
                        {"name": "ISTIO_META_INTERCEPTION_MODE", "value": "REDIRECT"},
                        {"name": "ISTIO_META_WORKLOAD_NAME", "value": pod_name},
                        {"name": "ISTIO_META_OWNER", "value": f"kubernetes://apis/apps/v1/namespaces/{namespace}/deployments/{pod_name}"}
                    ],
                    "resources": {
                        "limits": {"cpu": "2000m", "memory": "1024Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    },
                    "volumeMounts": [
                        {"name": "workload-socket", "mountPath": "/var/run/secrets/workload-spiffe-uds"},
                        {"name": "credential-socket", "mountPath": "/var/run/secrets/credential-uds"},
                        {"name": "workload-certs", "mountPath": "/var/run/secrets/workload-spiffe-credentials"},
                        {"name": "istio-envoy", "mountPath": "/etc/istio/proxy"},
                        {"name": "istio-data", "mountPath": "/var/lib/istio/data"},
                        {"name": "istio-podinfo", "mountPath": "/etc/istio/pod"}
                    ],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"add": ["NET_ADMIN", "NET_RAW"]},
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "runAsGroup": 1337,
                        "runAsNonRoot": True,
                        "runAsUser": 1337
                    }
                }
            }
            patches.append(sidecar_container)
            
            # Add Istio volumes
            istio_volumes = [
                {"name": "workload-socket", "emptyDir": {}},
                {"name": "credential-socket", "emptyDir": {}},
                {"name": "workload-certs", "emptyDir": {}},
                {"name": "istio-envoy", "emptyDir": {}},
                {"name": "istio-data", "emptyDir": {}},
                {"name": "istio-podinfo", "downwardAPI": {"items": [
                    {"path": "labels", "fieldRef": {"fieldPath": "metadata.labels"}},
                    {"path": "annotations", "fieldRef": {"fieldPath": "metadata.annotations"}}
                ]}}
            ]
            
            for volume in istio_volumes:
                volume_patch = {
                    "op": "add",
                    "path": "/spec/volumes/-", 
                    "value": volume
                }
                patches.append(volume_patch)
            
            # Add Istio annotations
            istio_annotations = {
                "sidecar.istio.io/status": json.dumps({
                    "initContainers": ["istio-init"],
                    "containers": ["istio-proxy"],
                    "volumes": [v["name"] for v in istio_volumes],
                    "imagePullSecrets": None,
                    "revision": "default"
                }),
                "sidecar.istio.io/inject": "false",  # Prevent re-injection
                "istio.io/rev": "default"
            }
            
            for key, value in istio_annotations.items():
                annotation_patch = {
                    "op": "add",
                    "path": f"/metadata/annotations/{key.replace('/', '~1')}",
                    "value": value
                }
                patches.append(annotation_patch)
            
            logger.info(f"Injected Istio sidecar with {len(patches)} patches")
        else:
            logger.info("Skipping sidecar injection - not enabled for this pod")
        
        return create_admission_response(request.get('uid'), allowed=True, patches=patches if patches else None)
    
    def handle_validate(self, admission_review):
        """Validate sidecar injection requirements"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        logger.info(f"Validating sidecar injection for pod: {pod.get('metadata', {}).get('name', 'unknown')}")
        
        # Simulate validation logic
        allowed = True
        message = "Sidecar injection validation passed"
        
        # Check for conflicting annotations
        annotations = pod.get('metadata', {}).get('annotations', {})
        if annotations.get('sidecar.istio.io/inject') == 'false' and annotations.get('istio-injection') == 'enabled':
            message = "Conflicting sidecar injection annotations detected"
            logger.warn(message)
            # Allow anyway for baseline training
        
        logger.info(f"Sidecar validation: {message}")
        
        return create_admission_response(request.get('uid'), allowed=allowed, message=message)
    
    def create_error_response(self, message):
        return create_admission_response("", allowed=False, message=message)
    
    def log_message(self, format, *args):
        logger.debug(format % args)

def main():
    port = 8443
    logger, ssl_context = setup_logging_and_ssl()
    server = HTTPServer(('0.0.0.0', port), IstioSidecarInjectorHandler)
    
    # Configure SSL if available
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info(f"Istio sidecar injector webhook server starting on HTTPS port {port}")
    else:
        logger.info(f"Istio sidecar injector webhook server starting on HTTP port {port}")
    
    try:
        logger.info("Starting sidecar injection activities...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Istio sidecar injector webhook server")
        server.shutdown()

if __name__ == '__main__':
    main()