#!/usr/bin/env python3
"""
Resource Quota Webhook Server
Simulates resource quota enforcement and validation
"""

import json
import logging
import time
import base64
import re
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

class ResourceQuotaWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            admission_review = json.loads(post_data.decode('utf-8'))
            
            logger.info(f"Processing resource quota request: {self.path}")
            
            if self.path == '/quota':
                response = self.handle_quota(admission_review)
            elif self.path == '/validate':
                response = self.handle_validate(admission_review)
            else:
                response = self.create_error_response("Unknown endpoint")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error processing resource quota: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_quota(self, admission_review):
        """Handle resource quota enforcement"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        
        logger.info(f"Enforcing resource quotas for pod: {pod_name} in namespace: {namespace}")
        
        patches = []
        
        # Check and enforce resource limits
        containers = pod.get('spec', {}).get('containers', [])
        
        for i, container in enumerate(containers):
            container_name = container.get('name', f'container-{i}')
            resources = container.get('resources', {})
            
            # Apply default resource limits if missing
            if not resources.get('limits'):
                logger.info(f"Applying default resource limits to container: {container_name}")
                
                default_limits = {
                    "op": "add",
                    "path": f"/spec/containers/{i}/resources/limits",
                    "value": {
                        "cpu": "500m",
                        "memory": "512Mi"
                    }
                }
                patches.append(default_limits)
            
            # Apply default resource requests if missing
            if not resources.get('requests'):
                logger.info(f"Applying default resource requests to container: {container_name}")
                
                default_requests = {
                    "op": "add", 
                    "path": f"/spec/containers/{i}/resources/requests",
                    "value": {
                        "cpu": "100m",
                        "memory": "128Mi"
                    }
                }
                patches.append(default_requests)
            
            # Enforce maximum resource limits
            limits = resources.get('limits', {})
            if limits:
                # Check CPU limit
                cpu_limit = limits.get('cpu', '0')
                if self.parse_cpu(cpu_limit) > self.parse_cpu('2000m'):
                    logger.warn(f"CPU limit too high for {container_name}, capping at 2000m")
                    cpu_cap = {
                        "op": "replace",
                        "path": f"/spec/containers/{i}/resources/limits/cpu",
                        "value": "2000m"
                    }
                    patches.append(cpu_cap)
                
                # Check memory limit
                memory_limit = limits.get('memory', '0')
                if self.parse_memory(memory_limit) > self.parse_memory('2Gi'):
                    logger.warn(f"Memory limit too high for {container_name}, capping at 2Gi")
                    memory_cap = {
                        "op": "replace",
                        "path": f"/spec/containers/{i}/resources/limits/memory", 
                        "value": "2Gi"
                    }
                    patches.append(memory_cap)
        
        # Add resource quota annotations
        quota_annotations = {
            "resource-quota.io/cpu-limit": "2000m",
            "resource-quota.io/memory-limit": "2Gi",
            "resource-quota.io/enforced-at": str(int(time.time())),
            "resource-quota.io/policy": "strict"
        }
        
        for key, value in quota_annotations.items():
            annotation_patch = {
                "op": "add",
                "path": f"/metadata/annotations/{key.replace('/', '~1')}",
                "value": value
            }
            patches.append(annotation_patch)
        
        # Add resource usage labels
        usage_labels = {
            "resource-quota.io/cpu-class": self.classify_cpu_usage(containers),
            "resource-quota.io/memory-class": self.classify_memory_usage(containers),
            "resource-quota.io/tier": "standard"
        }
        
        for key, value in usage_labels.items():
            label_patch = {
                "op": "add",
                "path": f"/metadata/labels/{key.replace('/', '~1')}",
                "value": value
            }
            patches.append(label_patch)
        
        logger.info(f"Applied {len(patches)} resource quota patches")
        
        return create_admission_response(request.get('uid'), allowed=True, patches=patches)
    
    def handle_validate(self, admission_review):
        """Validate resource quota compliance"""
        request = admission_review.get('request', {})
        pod = request.get('object', {})
        
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        logger.info(f"Validating resource quotas for pod: {pod_name}")
        
        allowed = True
        messages = []
        
        containers = pod.get('spec', {}).get('containers', [])
        
        for container in containers:
            container_name = container.get('name', 'unknown')
            resources = container.get('resources', {})
            
            # Validate resource limits
            limits = resources.get('limits', {})
            if limits:
                cpu_limit = limits.get('cpu')
                memory_limit = limits.get('memory')
                
                # Check for excessive resource requests
                if cpu_limit and self.parse_cpu(cpu_limit) > self.parse_cpu('4000m'):
                    messages.append(f"CPU limit {cpu_limit} exceeds maximum allowed (4000m) for container {container_name}")
                    # Allow anyway for baseline training
                
                if memory_limit and self.parse_memory(memory_limit) > self.parse_memory('4Gi'):
                    messages.append(f"Memory limit {memory_limit} exceeds maximum allowed (4Gi) for container {container_name}")
                    # Allow anyway for baseline training
            
            # Validate resource requests
            requests = resources.get('requests', {})
            if requests:
                cpu_request = requests.get('cpu')
                memory_request = requests.get('memory')
                
                if cpu_request and self.parse_cpu(cpu_request) > self.parse_cpu('2000m'):
                    messages.append(f"CPU request {cpu_request} exceeds recommended limit for container {container_name}")
                
                if memory_request and self.parse_memory(memory_request) > self.parse_memory('2Gi'):
                    messages.append(f"Memory request {memory_request} exceeds recommended limit for container {container_name}")
        
        message = "; ".join(messages) if messages else "Resource quota validation passed"
        
        if messages:
            logger.warn(f"Resource quota warnings: {message}")
        else:
            logger.info("Resource quota validation passed")
        
        return create_admission_response(request.get('uid'), allowed=allowed, message=message)
    
    def parse_cpu(self, cpu_str):
        """Parse CPU string to millicores"""
        if not cpu_str:
            return 0
        
        if cpu_str.endswith('m'):
            return int(cpu_str[:-1])
        elif cpu_str.endswith('n'):
            return int(cpu_str[:-1]) / 1000000
        else:
            return int(float(cpu_str) * 1000)
    
    def parse_memory(self, memory_str):
        """Parse memory string to bytes"""
        if not memory_str:
            return 0
        
        units = {
            'K': 1024, 'Ki': 1024,
            'M': 1024**2, 'Mi': 1024**2,
            'G': 1024**3, 'Gi': 1024**3,
            'T': 1024**4, 'Ti': 1024**4
        }
        
        for unit, multiplier in units.items():
            if memory_str.endswith(unit):
                return int(float(memory_str[:-len(unit)]) * multiplier)
        
        return int(memory_str)
    
    def classify_cpu_usage(self, containers):
        """Classify CPU usage level"""
        total_cpu = sum(self.parse_cpu(c.get('resources', {}).get('requests', {}).get('cpu', '0')) for c in containers)
        
        if total_cpu < 100:
            return "low"
        elif total_cpu < 500:
            return "medium"
        else:
            return "high"
    
    def classify_memory_usage(self, containers):
        """Classify memory usage level"""
        total_memory = sum(self.parse_memory(c.get('resources', {}).get('requests', {}).get('memory', '0')) for c in containers)
        
        if total_memory < 128 * 1024 * 1024:  # 128Mi
            return "low"
        elif total_memory < 512 * 1024 * 1024:  # 512Mi
            return "medium"
        else:
            return "high"
    
    def create_error_response(self, message):
        return create_admission_response("", allowed=False, message=message)
    
    def log_message(self, format, *args):
        logger.debug(format % args)

def main():
    port = 8443
    logger, ssl_context = setup_logging_and_ssl()
    server = HTTPServer(('0.0.0.0', port), ResourceQuotaWebhookHandler)
    
    # Configure SSL if available
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info(f"Resource quota webhook server starting on HTTPS port {port}")
    else:
        logger.info(f"Resource quota webhook server starting on HTTP port {port}")
    
    try:
        logger.info("Starting resource quota enforcement activities...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down resource quota webhook server")
        server.shutdown()

if __name__ == '__main__':
    main()