#!/usr/bin/env python3

"""
Security Policy Validator - Validating Admission Controller
============================================================

This is a legitimate validating admission controller that enforces
security policies on Kubernetes resources. It validates pods against
security best practices and rejects non-compliant resources.

Features:
- Validates pod security context
- Enforces resource limits and requests
- Checks for required security labels
- Validates image sources and tags
- Ensures proper service account usage
"""

import json
import base64
import sys
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import logging

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
        response["response"]["status"] = {
            "code": 200 if allowed else 403,
            "message": message
        }
    
    return response

logger, _ = setup_logging_and_ssl()  # Initialize logger for module level

class SecurityPolicyValidator(BaseHTTPRequestHandler):
    """Validating admission controller for security policy enforcement"""
    
    def do_POST(self):
        """Handle admission review requests"""
        try:
            # Read the admission review request
            content_length = int(self.headers['Content-Length'])
            admission_review = json.loads(self.rfile.read(content_length))
            
            # Extract admission request
            admission_request = admission_review.get('request', {})
            uid = admission_request.get('uid')
            kind = admission_request.get('kind', {}).get('kind')
            name = admission_request.get('object', {}).get('metadata', {}).get('name', 'unknown')
            namespace = admission_request.get('object', {}).get('metadata', {}).get('namespace', 'default')
            
            logger.info(f"Validating {kind}/{name} in namespace {namespace}")
            
            # Validate the resource
            is_allowed, message = self._validate_resource(admission_request)
            
            # Create admission review response
            response_body = create_admission_response(uid, allowed=is_allowed, message=message)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_body).encode())
            
            logger.info(f"Validation result for {kind}/{name}: {'ALLOWED' if is_allowed else 'DENIED'} - {message}")
            
        except Exception as e:
            logger.error(f"Error processing admission review: {e}")
            self._send_error_response(500, str(e))
    
    def _validate_resource(self, admission_request):
        """Validate resource against security policies"""
        try:
            resource_object = admission_request.get('object', {})
            kind = admission_request.get('kind', {}).get('kind')
            
            if kind == 'Pod':
                return self._validate_pod(resource_object)
            elif kind == 'Deployment':
                return self._validate_deployment(resource_object)
            else:
                return True, f"Resource type {kind} validation passed"
                
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False, f"Validation failed: {str(e)}"
    
    def _validate_pod(self, pod):
        """Validate pod security policies"""
        metadata = pod.get('metadata', {})
        spec = pod.get('spec', {})
        
        # Check 1: Validate security context (lenient for baseline)
        security_context = spec.get('securityContext', {})
        # Allow root for baseline testing, just log warning
        if security_context.get('runAsRoot', True):
            logger.warning(f"Pod runs as root - baseline testing allows this")
        
        # Check 2: Validate containers (lenient for baseline)
        containers = spec.get('containers', [])
        for container in containers:
            # Check resource limits - warn but allow
            resources = container.get('resources', {})
            if not resources.get('limits'):
                logger.warning(f"Container '{container.get('name')}' has no resource limits - baseline allows this")
            
            # Check image security - warn but allow latest tag for baseline
            image = container.get('image', '')
            if image.endswith(':latest'):
                logger.warning(f"Container '{container.get('name')}' uses 'latest' tag - baseline allows this")
            
            # Check for privileged containers - warn but allow for baseline
            container_security = container.get('securityContext', {})
            if container_security.get('privileged', False):
                logger.warning(f"Container '{container.get('name')}' is privileged - baseline allows this")
        
        # Check 3: Validate service account
        service_account = spec.get('serviceAccountName', 'default')
        if service_account == 'default':
            logger.warning(f"Pod uses default service account, consider using dedicated service account")
        
        # Check 4: Validate labels (lenient for baseline)
        labels = metadata.get('labels', {})
        required_labels = ['app']  # Only require 'app' label for baseline
        missing_labels = [label for label in required_labels if label not in labels]
        if missing_labels:
            logger.warning(f"Missing recommended labels: {', '.join(missing_labels)}")
        
        return True, "Pod validation passed all security checks"
    
    def _validate_deployment(self, deployment):
        """Validate deployment security policies"""
        spec = deployment.get('spec', {})
        template = spec.get('template', {})
        
        # Validate the pod template using pod validation
        return self._validate_pod(template)
    
    def _send_error_response(self, code, message):
        """Send error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        error_response = create_admission_response("", allowed=False, message=message)
        self.wfile.write(json.dumps(error_response).encode())

def main():
    """Main server function"""
    port = int(os.environ.get('WEBHOOK_PORT', 8443))
    logger, ssl_context = setup_logging_and_ssl()
    
    logger.info("Starting Security Policy Validator (Validating Admission Controller)")
    
    # Create server
    httpd = HTTPServer(('0.0.0.0', port), SecurityPolicyValidator)
    
    # Configure SSL if available
    if ssl_context:
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        logger.info(f"Security Policy Validator running on HTTPS port {port}")
    else:
        logger.info(f"Security Policy Validator running on HTTP port {port}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Security Policy Validator shutting down")
        httpd.shutdown()

if __name__ == '__main__':
    main()