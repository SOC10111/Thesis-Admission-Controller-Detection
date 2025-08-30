#!/usr/bin/env python3
"""
Cert-Manager Webhook Server
Simulates certificate management admission controller behavior

This baseline admission controller represents legitimate certificate management
behavior for training. It:
1. Mutates pods to inject TLS certificate volumes
2. Adds environment variables for certificate paths
3. Validates certificate configurations
4. Simulates certificate rotation operations

This generates normal admission controller patterns for the system to learn.
"""

import json
import logging
import time
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import ssl
import os

def setup_logging_and_ssl(cert_path='/etc/certs/tls.crt', key_path='/etc/certs/tls.key'):
    """Setup logging and SSL context for webhook server
    
    Admission controllers require TLS for secure communication with the API server.
    This function loads the TLS certificates generated during deployment.
    """
    # Configure logging to track webhook operations
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    # Create SSL context for HTTPS webhook endpoint
    ssl_context = None
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)
        logger.info("Loaded TLS certificates")
    else:
        logger.warning("TLS certificates not found, running without SSL")
    
    return logger, ssl_context

def create_admission_response(uid, allowed=True, message="", patches=None):
    """Create standardized AdmissionReview response
    
    Formats the response according to Kubernetes AdmissionReview API spec.
    Used to allow/deny pod creation and apply mutations.
    """
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

class CertManagerWebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for admission webhook requests
    
    Processes AdmissionReview requests from the Kubernetes API server
    when pods are created or modified.
    """
    
    def do_POST(self):
        """Handle POST requests containing AdmissionReview objects"""
        try:
            # Read the AdmissionReview request from Kubernetes
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            admission_review = json.loads(post_data.decode('utf-8'))
            
            logger.info(f"Processing admission request: {self.path}")
            
            if self.path == '/mutate':
                response = self.handle_mutate(admission_review)
            elif self.path == '/validate':
                response = self.handle_validate(admission_review)
            else:
                response = self.create_error_response("Unknown endpoint")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_mutate(self, admission_review):
        """Handle pod mutation for certificate injection"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        logger.info(f"Mutating pod: {pod.get('metadata', {}).get('name', 'unknown')}")
        
        # Simulate certificate injection
        patches = []
        
        # Add certificate volume
        cert_volume = {
            "op": "add",
            "path": "/spec/volumes/-",
            "value": {
                "name": "cert-manager-certs",
                "secret": {
                    "secretName": "cert-manager-ca-certs"
                }
            }
        }
        patches.append(cert_volume)
        
        # Add certificate volume mount to first container
        if pod.get('spec', {}).get('containers'):
            cert_mount = {
                "op": "add", 
                "path": "/spec/containers/0/volumeMounts/-",
                "value": {
                    "name": "cert-manager-certs",
                    "mountPath": "/etc/ssl/certs/ca-certificates.crt",
                    "readOnly": True
                }
            }
            patches.append(cert_mount)
        
        # Add certificate annotation
        cert_annotation = {
            "op": "add",
            "path": "/metadata/annotations/cert-manager.io~1certificate-name",
            "value": f"auto-cert-{int(time.time())}"
        }
        patches.append(cert_annotation)
        
        logger.info(f"Applied {len(patches)} certificate mutations")
        
        return create_admission_response(request.get('uid'), allowed=True, patches=patches)
    
    def handle_validate(self, admission_review):
        """Validate certificate requirements"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        logger.info(f"Validating pod: {pod.get('metadata', {}).get('name', 'unknown')}")
        
        # Simulate certificate validation
        annotations = pod.get('metadata', {}).get('annotations', {})
        
        # Check for required certificate annotations
        allowed = True
        message = "Certificate validation passed"
        
        if 'cert-manager.io/issuer' not in annotations:
            logger.warn("Pod missing certificate issuer annotation")
            # Allow anyway for baseline training
        
        logger.info(f"Certificate validation: {message}")
        
        return create_admission_response(request.get('uid'), allowed=allowed, message=message)
    
    def create_error_response(self, message):
        return create_admission_response("", allowed=False, message=message)
    
    def log_message(self, format, *args):
        # Suppress default HTTP logs, use our logger
        logger.debug(format % args)

def main():
    port = 8443
    logger, ssl_context = setup_logging_and_ssl()
    server = HTTPServer(('0.0.0.0', port), CertManagerWebhookHandler)
    
    # Configure SSL if available
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info(f"Cert-Manager webhook server starting on HTTPS port {port}")
    else:
        logger.info(f"Cert-Manager webhook server starting on HTTP port {port}")
    
    try:
        # Simulate ongoing certificate management activities
        logger.info("Starting certificate management activities...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down cert-manager webhook server")
        server.shutdown()

if __name__ == '__main__':
    main()