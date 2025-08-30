#!/usr/bin/env python3
"""
ML for Malicious Admission controller Detection

This Proof of Concept analyzes Falco security events to detect potentially malicious
admission controllers in Kubernetes. It uses machine learning to classify admission controller 
behavior by extracting features from Falco security events.

Core functionality:
- Parses Falco JSON security events from Kubernetes clusters
- Identifies admission controller related events through pattern matching
- Extracts 43 behavioral features from each detected event
- Uses Random Forest and Isolation Forest models for classification
- Provides interactive feedback system for improving accuracy
- Generates detailed security analysis reports

Developed for research and as a Proof of Concept into Kubernetes admission controller security patterns.
"""

import os
import sys
import json
import time
import sqlite3
import argparse
import logging
import joblib
import numpy as np
import pandas as pd
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import hashlib
import re

# Verify machine learning dependencies are available
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.feature_selection import SelectKBest, f_classif
    ML_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Missing ML dependencies: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class AdmissionControllerEvent:
    # this holds all the data about an admission controller event
    timestamp: str
    admission_controller_name: str
    namespace: str
    pod_name: str
    container_name: str
    image: str
    process_name: str
    command: str
    rule: str  # Falco rule that triggered the event
    
    # Security features for ML
    privileged: bool
    capabilities: List[str]
    host_mounts: List[str]
    env_vars: Dict[str, str]
    
    # Behavioral features
    network_activity: bool
    file_operations: int
    syscall_frequency: float
    
    # ML classification results
    classification: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None

class AdmissionControllerDetectionPipeline:
    """
    Main pipeline for admission controller threat detection.
    
    This class handles the complete workflow from Falco event ingestion
    to threat classification and reporting. It uses behavioral analysis
    to identify potentially malicious admission controllers.
    """
    
    # Classification thresholds determined through testing
    FEATURE_COUNT = 43
    RISK_THRESHOLD_MALICIOUS = 0.7
    RISK_THRESHOLD_SUSPICIOUS = 0.4
    RANDOM_FOREST_ESTIMATORS = 100
    ISOLATION_FOREST_CONTAMINATION = 0.1
    
    # Standard file names for model and data storage
    MODEL_FILE = "ml_admission_controller_ident.pkl"
    DATABASE_FILE = "ml_admission_controller_ident.db"
    BASELINE_DATA_FILE = "baseline.json"
    FEATURE_NAMES_FILE = "feature_names.json"
    
    def __init__(self):
        """Initialize detection pipeline with standardized paths and components"""
        # Set up the directory where all detection outputs will be stored
        self.test_results_dir = Path("./test-results")
        self.test_results_dir.mkdir(exist_ok=True)
        
        # Initialize ML components (training occurs separately)
        self.random_forest = None  # Primary classifier for threat detection
        self.isolation_forest = None  # Anomaly detector for unusual patterns
        self.scaler = StandardScaler()  # Normalizes features for consistent scaling
        self.feature_names = []  # Stores names of the 43 extracted features
        
        # Set up file paths for model persistence and results
        self.classifier_path = self.test_results_dir / self.MODEL_FILE
        self.db_path = self.test_results_dir / self.DATABASE_FILE
        
        # Initialize SQLite database for storing detection results and feedback
        self._init_database()
        logger.info("Database initialized")
        logger.info("Admission Controller Detection Pipeline initialized")
    
    def _init_database(self):
        """
        Initialize SQLite database with tables for storing detection results.
        
        Creates tables for:
        - ml_detections: Main results table with classification data
        - ml_feedback_overrides: User corrections for improving model accuracy
        - controller_behavioral_profiles: Learned patterns per controller type
        - admission_controller_events: Legacy compatibility table
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")  # Enable Write-Ahead Logging for better performance
        cursor = conn.cursor()
        
        # Primary table: stores ML classification results for each detected event
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                admission_controller_name TEXT NOT NULL,
                namespace TEXT,
                pod_name TEXT,
                container_name TEXT,
                image TEXT,
                process_name TEXT,
                command TEXT,
                privileged BOOLEAN,
                capabilities TEXT,
                host_mounts TEXT,  
                env_vars TEXT,
                network_activity BOOLEAN,
                file_operations INTEGER,
                syscall_frequency REAL,
                classification TEXT,
                risk_score REAL,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                -- Enhanced columns for storing complete event context (enables better retraining)
                full_falco_event TEXT,
                extracted_features_json TEXT,
                behavioral_signature TEXT
            )
        """)
        
        # Feedback table: stores user corrections to improve model accuracy
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_feedback_overrides (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER,
                admission_controller_name TEXT NOT NULL,
                original_classification TEXT,
                corrected_classification TEXT,
                analyst_comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (detection_id) REFERENCES ml_detections (id)
            )
        """)
        
        # Behavioral profiles: learned patterns and baselines for each controller type
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS controller_behavioral_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                controller_name TEXT UNIQUE NOT NULL,
                controller_type TEXT,
                command_patterns TEXT,
                file_patterns TEXT,
                network_patterns TEXT,
                port_patterns TEXT,
                entropy_baseline REAL,
                entropy_std_dev REAL,
                typical_risk_score REAL,
                event_count INTEGER DEFAULT 0,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                confidence_level REAL DEFAULT 0.0
            )
        """)
        
        # Legacy table: maintains backward compatibility with existing integrations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admission_controller_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                admission_controller_name TEXT NOT NULL,
                namespace TEXT,
                pod_name TEXT,
                container_name TEXT,
                image TEXT,
                process_name TEXT,
                command TEXT,
                privileged BOOLEAN,
                capabilities TEXT,
                host_mounts TEXT,  
                env_vars TEXT,
                network_activity BOOLEAN,
                file_operations INTEGER,
                syscall_frequency REAL,
                classification TEXT,
                risk_score REAL,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    
    def train_from_json(self, json_file_path: str):
        """
        Train ML models from Falco JSON log file.
        
        Process:
        1. Parse Falco events from JSON file
        2. Filter for admission controller related events
        3. Extract 43 behavioral features from each event
        4. Auto-label events based on risk score calculations
        5. Train Random Forest classifier and Isolation Forest anomaly detector
        6. Save trained models and generate analysis report
        
        Args:
            json_file_path (str): Path to Falco JSON log file
        """
        # Validate input file exists before processing
        if not json_file_path:
            raise ValueError("JSON file path is needed")
        
        if not os.path.exists(json_file_path):
            raise FileNotFoundError(f"JSON file not found: {json_file_path}")
        
        logger.info(f"Training classifiers from: {json_file_path}")
        
        # Parse JSON file and filter for admission controller related events
        events, falco_events = self._parse_admission_controller_events(json_file_path)
        
        if not events:
            logger.warning("No admission controller events found in JSON file")
            logger.info("This may be due to missing Kubernetes metadata in Falco logs")
            logger.info("Ensure Falco has Kubernetes enrichment enabled")
            raise ValueError("No admission controller events found in JSON file")
        
        logger.info(f"Found {len(events)} admission controller events")
        
        # Convert events to 43 numerical features for ML processing
        features_df = self._extract_ml_features(events)
        
        # Create feature matrix for training
        X = features_df.values
        
        # Auto-label events as MALICIOUS/SUSPICIOUS/LEGITIMATE based on risk scores
        y = self._generate_risk_labels(events, features_df)
        
        # Normalize features to 0-1 range for better ML performance
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Random Forest as primary classifier (100 trees for robustness)
        logger.info("Training Random Forest classifier...")
        self.random_forest = RandomForestClassifier(n_estimators=self.RANDOM_FOREST_ESTIMATORS, random_state=42)
        self.random_forest.fit(X_scaled, y)
        
        # Train Isolation Forest to detect anomalous behavior patterns
        logger.info("Training Isolation Forest for anomaly detection...")
        self.isolation_forest = IsolationForest(contamination=self.ISOLATION_FOREST_CONTAMINATION, random_state=42)
        self.isolation_forest.fit(X_scaled)
        
        # Apply trained classifiers to all events and calculate risk scores
        predictions = []
        for i, event in enumerate(events):
            feature_vector = X_scaled[i:i+1]
            
            # Random Forest prediction
            rf_pred = self.random_forest.predict(feature_vector)[0]
            rf_prob = self.random_forest.predict_proba(feature_vector)[0]
            
            # Isolation Forest anomaly score
            anomaly_score = self.isolation_forest.decision_function(feature_vector)[0]
            
            # Calculate risk score and classification
            risk_score = self._calculate_risk_score(rf_prob, anomaly_score, event)
            classification = self._classify_risk(risk_score)
            confidence = max(rf_prob)
            
            # Update event with ML results
            event.classification = classification
            event.risk_score = risk_score
            event.confidence = confidence
            
            predictions.append(event)
        
        # Apply feedback overrides before storing results
        predictions = self._apply_feedback_overrides(predictions)
        
        # Save trained classifiers
        self._save_models()
        
        # Store results in database with full Falco event context
        self._store_events_with_context(predictions, falco_events)
        
        # Compute training metrics for structured report
        try:
            y_pred = self.random_forest.predict(X_scaled)
            train_accuracy = accuracy_score(y, y_pred)
            train_report = classification_report(y, y_pred)
        except Exception:
            train_accuracy = None
            train_report = None
        
        # Generate only the structured training report with ML factors
        is_baseline = "baseline" in json_file_path.lower()
        
        # Apply feedback overrides to events used for reporting as well
        events_for_report = self._apply_feedback_overrides(events.copy())
        
        # For activity reports, exclude baseline controllers
        if not is_baseline:
            baseline_controllers = {'cert-manager-webhook', 'istio-sidecar-injector', 'resource-quota-webhook', 'security-policy-validator'}
            filtered_events = [event for event in events_for_report if event.admission_controller_name not in baseline_controllers]
            logger.info(f"Filtered from {len(events_for_report)} to {len(filtered_events)} events (excluding baseline controllers)")
            
            if filtered_events:
                self._generate_structured_training_report(filtered_events, y, train_accuracy, train_report, is_baseline)
            else:
                logger.warning("No new admission controllers found after filtering baseline controllers")
                # Generate empty activity report showing that only baseline controllers were detected
                self._generate_empty_activity_report(events_for_report, baseline_controllers)
        else:
            self._generate_structured_training_report(events_for_report, y, train_accuracy, train_report, is_baseline)
        
        logger.info("ML training completed successfully")
    
    def controller_report(self, input_file: str = None, output_file: str = None):
        """Admission controller threat report grouped by controller name"""        
        # Validate input file if provided
        if input_file and not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        logger.info("Generating admission controller threat report")
        
        # Generate report from input file
        if input_file:
            events, falco_events = self._parse_admission_controller_events(input_file)
            if not events:
                raise ValueError("No admission controller events found in input file")
            
            # Determine output file - use standard naming without hardcoded baseline_report.txt
            if output_file:
                report_file = Path(output_file)
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_file = self.test_results_dir / f"report_{timestamp}.txt"
            
            # Apply feedback overrides before generating report
            events = self._apply_feedback_overrides(events)
            
            # Generate report using the current ML report system
            is_baseline = "baseline" in input_file.lower()
            self._generate_controller_report(events, is_baseline)
            
        else:
            # Generate report from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query events grouped by admission controller, applying feedback overrides
            cursor.execute("""
                SELECT 
                    ace.admission_controller_name,
                    COALESCE(mfo.corrected_classification, ace.classification) as classification,
                    COUNT(*) as event_count,
                    CASE 
                        WHEN COALESCE(mfo.corrected_classification, ace.classification) = 'LEGITIMATE' THEN 0.2
                        WHEN COALESCE(mfo.corrected_classification, ace.classification) = 'SUSPICIOUS' THEN 0.5
                        WHEN COALESCE(mfo.corrected_classification, ace.classification) = 'MALICIOUS' THEN 0.75
                        ELSE AVG(ace.risk_score)
                    END as avg_risk_score,
                    CASE 
                        WHEN COALESCE(mfo.corrected_classification, ace.classification) = 'LEGITIMATE' THEN 0.2
                        WHEN COALESCE(mfo.corrected_classification, ace.classification) = 'SUSPICIOUS' THEN 0.5
                        WHEN COALESCE(mfo.corrected_classification, ace.classification) = 'MALICIOUS' THEN 0.75
                        ELSE MAX(ace.risk_score)
                    END as max_risk_score
                FROM ml_detections ace
                LEFT JOIN ml_feedback_overrides mfo 
                    ON ace.admission_controller_name = mfo.admission_controller_name
                GROUP BY ace.admission_controller_name, COALESCE(mfo.corrected_classification, ace.classification)
                ORDER BY ace.admission_controller_name, avg_risk_score DESC
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            if not results:
                logger.warning("No events found in database")
                return
            
            # Generate report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.test_results_dir / f"report_{timestamp}.txt"
            
            with open(report_file, 'w') as f:
                f.write("ADMISSION CONTROLLER THREAT REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Group results by admission controller
                controller_data = {}
                for row in results:
                    controller_name, classification, event_count, avg_risk, max_risk = row
                    if controller_name not in controller_data:
                        controller_data[controller_name] = []
                    controller_data[controller_name].append({
                        'classification': classification,
                        'event_count': event_count,
                        'avg_risk_score': avg_risk,
                        'max_risk_score': max_risk
                    })
                
                # Write grouped report
                for controller_name, data in controller_data.items():
                    f.write(f"Controller: {controller_name}\n")
                    f.write("-" * 34 + "\n")
                    
                    total_events = sum(item['event_count'] for item in data)
                    
                    # Get all risk scores for proper max/avg calculation
                    all_classifications = []
                    for item in data:
                        all_classifications.extend([item['classification']] * item['event_count'])
                    
                    # Build classification string
                    classification_counts = {}
                    for item in data:
                        classification_counts[item['classification']] = item['event_count']
                    
                    classifications_str = ', '.join([f"{cls}({count})" for cls, count in classification_counts.items()])
                    
                    # Calculate proper max and average risk scores
                    max_risk = max(item['max_risk_score'] for item in data)
                    weighted_sum = sum(item['avg_risk_score'] * item['event_count'] for item in data)
                    avg_risk = weighted_sum / total_events if total_events > 0 else 0
                    
                    f.write(f"Events: {total_events}\n")
                    f.write(f"Classifications: {classifications_str}\n")
                    f.write(f"Risk Score: {max_risk:.3f} (max) | {avg_risk:.3f} (avg)\n")
                    
                    # Add ML Classification Factors
                    # Query the actual feature values from the database
                    cursor2 = sqlite3.connect(self.db_path).cursor()
                    cursor2.execute("""
                        SELECT * FROM ml_detections 
                        WHERE admission_controller_name = ?
                        LIMIT 1
                    """, (controller_name,))
                    
                    sample_row = cursor2.fetchone()
                    if sample_row and len(sample_row) > 20:
                        # Extract feature columns (they start after the basic columns)
                        # Features are stored in columns after the main detection data
                        feature_names = ['command_obfuscation', 'suspicious_binary_execution', 
                                       'process_suspicious_commands', 'network_activity_detected', 
                                       'outbound_connections']
                        
                        f.write("ML Classification Factors (Active Features):\n")
                        
                        # For now, show the key features that would affect classification
                        # These are simplified since we need the actual feature extraction
                        if max_risk < 0.4:  # LEGITIMATE
                            f.write("  - All features within normal baseline parameters\n")
                        elif max_risk < 0.7:  # SUSPICIOUS  
                            f.write("  - Some elevated activity detected\n")
                        else:  # MALICIOUS
                            f.write("  - Multiple high-risk indicators detected\n")
                    
                    cursor2.close()
                    f.write("\n")
        
        logger.info(f"Report generated: {report_file}")
    
    def feedback_review(self):
        """Interactive feedback review system"""
        import sys
        
        # Check if running in interactive mode
        if not sys.stdin.isatty():
            print("Error: Feedback review requires an interactive terminal.")
            print("Please run this command in an interactive shell, not as a script.")
            print("\nAlternatively, use the batch feedback option:")
            print("python3 analysis/admission_controller_ml.py batch-feedback --controller <name> --classification <LEGITIMATE|SUSPICIOUS|MALICIOUS> [--comment <text>]")
            return
        
        print("ML Feedback Review System")
        print("=" * 50)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all controllers and their current classifications
        cursor.execute("""
            SELECT DISTINCT admission_controller_name, classification, COUNT(*) as count,
                   AVG(risk_score) as avg_risk, MAX(risk_score) as max_risk
            FROM ml_detections
            GROUP BY admission_controller_name, classification
            ORDER BY admission_controller_name, avg_risk DESC
        """)
        
        results = cursor.fetchall()
        
        if not results:
            print("No controllers found in database. Please train classifiers first.")
            conn.close()
            return
        
        # Display all controllers and their classifications
        print("\nCurrent Controller Classifications:")
        print("-" * 40)
        
        controller_data = {}
        for row in results:
            controller_name, classification, count, avg_risk, max_risk = row
            if controller_name not in controller_data:
                controller_data[controller_name] = []
            controller_data[controller_name].append({
                'classification': classification or 'UNKNOWN',
                'count': count,
                'avg_risk': avg_risk or 0.0,
                'max_risk': max_risk or 0.0
            })
        
        for controller_name, data in controller_data.items():
            print(f"\nController: {controller_name}")
            total_events = sum(item['count'] for item in data)
            print(f"  Total Events: {total_events}")
            for item in data:
                print(f"    {item['classification']}: {item['count']} events (avg risk: {item['avg_risk']:.3f})")
        
        print(f"\nAvailable Controllers: {list(controller_data.keys())}")
        print("Enter 'exit' to quit feedback review")
        
        while True:
            try:
                try:
                    controller_name = input("\nEnter controller name to review: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nFeedback review interrupted by user")
                    break
                
                if controller_name.lower() == 'exit':
                    break
                
                if controller_name not in controller_data:
                    print("Controller not found. Available controllers:")
                    for name in controller_data.keys():
                        print(f"  - {name}")
                    continue
                
                # Get current classification for this controller
                cursor.execute("""
                    SELECT classification, COUNT(*) as count
                    FROM ml_detections
                    WHERE admission_controller_name = ?
                    GROUP BY classification
                    ORDER BY count DESC
                """, (controller_name,))
                
                classifications = cursor.fetchall()
                
                print(f"\nController: {controller_name}")
                print("Current Classifications:")
                for cls, count in classifications:
                    print(f"  {cls or 'UNKNOWN'}: {count} events")
                
                # Check for existing feedback override
                cursor.execute("""
                    SELECT corrected_classification, analyst_comment
                    FROM ml_feedback_overrides
                    WHERE admission_controller_name = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (controller_name,))
                
                existing_override = cursor.fetchone()
                
                if existing_override:
                    corrected_cls, comment = existing_override
                    print(f"Existing Override: {corrected_cls}")
                    if comment:
                        print(f"Comment: {comment}")
                else:
                    print("No existing override")
                
                print("\nOptions: LEGITIMATE, SUSPICIOUS, MALICIOUS")
                try:
                    corrected_classification = input("Enter corrected classification: ").strip().upper()
                except (EOFError, KeyboardInterrupt):
                    print("\nClassification input interrupted")
                    break
                
                if corrected_classification not in ['LEGITIMATE', 'SUSPICIOUS', 'MALICIOUS']:
                    print("Invalid classification. Must be LEGITIMATE, SUSPICIOUS, or MALICIOUS")
                    continue
                
                try:
                    comment = input("Enter optional comment: ").strip()
                except (EOFError, KeyboardInterrupt):
                    comment = ""
                    print("\nComment input skipped")
                
                # Get the most common original classification for this controller
                cursor.execute("""
                    SELECT classification, COUNT(*) as count
                    FROM ml_detections
                    WHERE admission_controller_name = ?
                    GROUP BY classification
                    ORDER BY count DESC
                    LIMIT 1
                """, (controller_name,))
                
                original_result = cursor.fetchone()
                original_classification = original_result[0] if original_result else 'UNKNOWN'
                
                # Store the feedback override
                cursor.execute("""
                    INSERT INTO ml_feedback_overrides 
                    (admission_controller_name, original_classification, corrected_classification, analyst_comment)
                    VALUES (?, ?, ?, ?)
                """, (controller_name, original_classification, corrected_classification, comment))
                
                # Update all detections for this controller
                cursor.execute("""
                    UPDATE ml_detections
                    SET classification = ?
                    WHERE admission_controller_name = ?
                """, (corrected_classification, controller_name))
                
                conn.commit()
                print("Feedback recorded and detections updated successfully")
                
                # Retrain classifiers with updated classifications
                print("Retraining classifiers with corrected classification...")
                if self._retrain_models_with_feedback():
                    print("Classifiers updated successfully with your feedback")
                else:
                    print("Warning: Classifier retraining failed, but database was updated")
                
            except (ValueError, KeyboardInterrupt):
                print("\nFeedback review interrupted")
                break
            except Exception as e:
                print(f"Error: {e}")
                continue
        
        conn.close()
        print("Feedback review completed")
    
    def batch_feedback(self, controller_name: str, classification: str, comment: str = ""):
        """Non-interactive batch feedback for specific controller"""
        if classification.upper() not in ['LEGITIMATE', 'SUSPICIOUS', 'MALICIOUS']:
            print(f"Error: Invalid classification '{classification}'. Must be LEGITIMATE, SUSPICIOUS, or MALICIOUS")
            return False
        
        classification = classification.upper()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if controller exists
        cursor.execute("""
            SELECT COUNT(*) FROM ml_detections 
            WHERE admission_controller_name = ?
        """, (controller_name,))
        
        count = cursor.fetchone()[0]
        if count == 0:
            print(f"Error: Controller '{controller_name}' not found in database")
            conn.close()
            return False
        
        print(f"Updating classification for controller '{controller_name}' to '{classification}'")
        print(f"Found {count} events to update")
        
        # Get the most common original classification for this controller
        cursor.execute("""
            SELECT classification, COUNT(*) as count
            FROM ml_detections
            WHERE admission_controller_name = ?
            GROUP BY classification
            ORDER BY count DESC
            LIMIT 1
        """, (controller_name,))
        
        original_result = cursor.fetchone()
        original_classification = original_result[0] if original_result else 'UNKNOWN'
        
        # Store the feedback override
        cursor.execute("""
            INSERT INTO ml_feedback_overrides 
            (admission_controller_name, original_classification, corrected_classification, analyst_comment)
            VALUES (?, ?, ?, ?)
        """, (controller_name, original_classification, classification, comment))
        
        # Update all detections for this controller
        cursor.execute("""
            UPDATE ml_detections
            SET classification = ?
            WHERE admission_controller_name = ?
        """, (classification, controller_name))
        
        conn.commit()
        conn.close()
        
        print("Feedback recorded and detections updated successfully")
        
        # Retrain classifiers with updated classifications
        print("Retraining classifiers with corrected classification...")
        if self._retrain_models_with_feedback():
            print("Classifiers updated successfully with your feedback")
            return True
        else:
            print("Warning: Classifier retraining failed, but database was updated")
            return False
    
    def deploy_baseline(self, duration: int = 600):
        """Deploy baseline admission controllers (internal use by main.sh)"""
        logger.info(f"Deploying baseline admission controllers for {duration} seconds")
        
        import subprocess
        import os
        
        # Use the proper baseline deployment script
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        baseline_script = os.path.join(project_dir, 'setup', 'deploy_baseline.sh')
        
        if not os.path.exists(baseline_script):
            logger.error(f"Baseline deployment script not found: {baseline_script}")
            return
        
        try:
            logger.info("Running baseline deployment script...")
            result = subprocess.run([
                'bash', baseline_script
            ], capture_output=True, text=True, timeout=duration + 60)
            
            if result.returncode != 0:
                logger.error(f"Baseline deployment failed: {result.stderr}")
                return
            
            logger.info("Baseline controllers deployed successfully")
            logger.info("Controllers: cert-manager-webhook, istio-sidecar-injector, resource-quota-webhook, security-policy-validator")
            logger.info("Namespace: baseline-test")
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Baseline deployment timed out after {duration + 60} seconds")
        except Exception as e:
            logger.error(f"Failed to deploy baseline controllers: {e}")
    
    def deploy_malicious(self, duration: int = 600):
        """Deploy malicious admission controller (internal use by main.sh)"""
        logger.info(f"Deploying malicious admission controller for {duration} seconds")
        
        # Deploy malicious admission controller
        self._deploy_malicious_controller()
        
        # Wait for deployment to stabilize
        time.sleep(30)
        
        # Generate webhook-triggering workloads to create admission controller events
        self._generate_malicious_workloads(duration)
        
        logger.info("Malicious controller deployed successfully")
    
    def _parse_admission_controller_events(self, json_file_path: str) -> Tuple[List[AdmissionControllerEvent], List[dict]]:
        """Parse admission controller events from Falco JSON log file
        
        Returns:
            Tuple of (parsed_events, original_falco_events) for full context preservation
        """
        events = []
        falco_events = []  # Store original Falco events for behavioral analysis
        
        with open(json_file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                
                try:
                    event_data = json.loads(line)
                    
                    # Extract admission controller name first - this is the primary filter
                    controller_name = self._extract_controller_name(event_data)
                    if not controller_name:
                        continue
                    
                    # Extract from both top level and output_fields for Falco compatibility
                    output_fields = event_data.get('output_fields', {})
                    
                    # Create event object with proper field mapping
                    event = AdmissionControllerEvent(
                        timestamp=event_data.get('time', datetime.now().isoformat()),
                        admission_controller_name=controller_name,
                        namespace=self._extract_namespace_context(output_fields, event_data, controller_name),
                        pod_name=self._extract_pod_context(output_fields, event_data, controller_name),
                        container_name=self._extract_container_context(output_fields, event_data),
                        image=output_fields.get('container.image.repository') or event_data.get('container_image', 'unknown'),
                        process_name=output_fields.get('proc.name') or event_data.get('proc_name', 'unknown'),
                        command=output_fields.get('proc.cmdline') or event_data.get('proc_cmdline', ''),
                        rule=event_data.get('rule', ''),  # Falco rule that triggered the event
                        privileged=event_data.get('privileged', False),
                        capabilities=event_data.get('proc_pcaps', []) if isinstance(event_data.get('proc_pcaps'), list) else [],
                        host_mounts=self._extract_host_mounts(event_data),
                        env_vars=event_data.get('proc_env', {}) if isinstance(event_data.get('proc_env'), dict) else {},
                        network_activity=self._detect_network_activity(event_data),
                        file_operations=self._count_file_operations(event_data),
                        syscall_frequency=event_data.get('syscall_frequency', 0.0)
                    )
                    
                    events.append(event)
                    falco_events.append(event_data)  # Store original for full context
                    
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.debug(f"Error parsing line {line_num}: {e}")
                    continue
        
        logger.info(f"Parsed {len(events)} admission controller events from {json_file_path}")
        return events, falco_events
    
    def _is_admission_controller_event(self, event_data: Dict) -> bool:
        """
        Determine if a Falco event is related to admission controller activity.
        
        Uses multiple detection methods:
        - Keyword matching in pod/container names
        - Certificate mount operations
        - Network requests to webhook endpoints
        - Process patterns typical of admission controllers
        
        Args:
            event_data (Dict): Falco event data structure
            
        Returns:
            bool: True if event appears to be admission controller related
        """
        
        # Extract output_fields for Falco compatibility
        output_fields = event_data.get('output_fields', {})
        
        # Primary indicators: keywords that strongly suggest admission controller activity
        primary_indicators = [
            'webhook', 'admission', 'mutating', 'validating',
            'admission-controller', 'webhook-server'
        ]
        
        # Secondary patterns: more specific webhook operation indicators
        webhook_patterns = [
            'webhook-certs',
            'admission-controller-certs',
            'admissionreview',
            'mutate', 'validate'
        ]
        
        # Extract text from all relevant event fields for pattern matching
        check_fields = [
            # Standard Falco event fields
            event_data.get('k8s_pod_name', ''),
            event_data.get('container_name', ''),  
            event_data.get('proc_name', ''),
            event_data.get('rule', ''),
            event_data.get('container_image', ''),
            event_data.get('proc_cmdline', ''),
            event_data.get('fd_name', ''),
            event_data.get('k8s_ns_name', ''),
            # Newer Falco output_fields format
            str(output_fields.get('k8s.pod.name', '')),
            str(output_fields.get('container.name', '')),
            str(output_fields.get('proc.name', '')),
            str(output_fields.get('container.image.repository', '')),
            str(output_fields.get('proc.cmdline', '')),
            str(output_fields.get('k8s.ns.name', ''))
        ]
        
        combined_text = ' '.join(check_fields).lower()
        
        # Check for primary indicators (high confidence detection)
        if any(indicator in combined_text for indicator in primary_indicators):
            return True
            
        # Detect network requests to admission controller webhook endpoints
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        
        if command and proc_name in ['wget', 'curl', 'http']:
            # Known patterns for admission controller service URLs
            webhook_service_patterns = [
                'webhook.svc.cluster.local',
                'admission.svc.cluster.local', 
                'mutating.svc.cluster.local',
                'validating.svc.cluster.local',
                '-webhook.',
                '-admission-',
                'controller.svc'
            ]
            
            # Check for HTTPS traffic on standard webhook port
            webhook_port_pattern = ':443/'
            
            if (any(pattern in command.lower() for pattern in webhook_service_patterns) or 
                webhook_port_pattern in command):
                return True
        
        # Certificate mount operations are strong indicators of admission controllers
        if command and proc_name in ['mount', 'umount']:
            # Filter for webhook-specific certificates (exclude generic kube-api-access)
            if any(pattern in command for pattern in ['webhook-certs', 'admission-controller-certs']):
                return True
        
        # Exclude metrics-server (monitoring infrastructure, not admission control)
        if proc_name in ['metrics-server'] or 'metrics-server' in combined_text:
            return False
        
        # Check for additional webhook-specific patterns
        if any(pattern in combined_text for pattern in webhook_patterns):
            return True
        
        # Network tools in containers may indicate suspicious activity
        if proc_name in ['wget', 'curl', 'nc', 'netcat', 'ssh', 'scp']:
            # Network tools are uncommon in typical container workloads
            if any(ctx in combined_text for ctx in ['container', 'pod', 'k8s']):
                return True
        
        # Additional check for admission controller certificate mount operations
        if proc_name in ['mount', 'umount'] and command:
            # Focus on webhook certificates only
            if any(pattern in command for pattern in ['webhook-certs', 'admission-controller-certs']):
                return True
            
        # Binary execution outside base image may indicate malicious activity
        if 'executing binary not part of base image' in event_data.get('rule', '').lower():
            # Exclude known Kubernetes system processes
            system_processes = ['dockerd', 'containerd', 'kubelet', 'kube-proxy', 'etcd']
            if not any(sys_proc in command.lower() for sys_proc in system_processes):
                return True
            
        # Check for file system operations that could indicate malicious activity
        if proc_name in ['cp', 'mv', 'chmod', 'chown'] and '/etc/' in command:
            return True
            
        # Check for webhook-specific network operations only
        fd_name = event_data.get('fd_name', '') or str(output_fields.get('fd.name', ''))
        if fd_name and any(webhook_pattern in fd_name.lower() for webhook_pattern in ['webhook', 'admission']):
            return True
        
        # Check for webhook-specific certificate operations only
        if any(webhook_cert in combined_text for webhook_cert in ['webhook-cert', 'admission-cert']):
            return True
        
        return False
    
    def _extract_controller_name(self, event_data: Dict) -> Optional[str]:
        """
        Extract admission controller name from Falco event data.
        
        Uses multiple extraction methods in priority order:
        1. Namespace and pod name mapping
        2. Certificate operation path analysis
        3. Kubelet pod UUID extraction
        4. Container context analysis
        5. Process and command pattern matching
        
        Args:
            event_data (Dict): Falco event data structure
            
        Returns:
            Optional[str]: Admission controller name if identifiable, None otherwise
        """
        output_fields = event_data.get('output_fields', {})
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        
        # Method 1: Extract from namespace and pod name context
        namespace = output_fields.get('k8s.ns.name', '') or event_data.get('k8s_ns_name', '')
        pod_name = output_fields.get('k8s.pod.name', '') or event_data.get('k8s_pod_name', '')
        
        # Extract namespace and pod information from event fields
        if namespace and namespace != 'None' and pod_name and pod_name != 'None':
            # Map known test namespaces to their admission controllers
            namespace_controllers = {
                'baseline-test': self._get_baseline_controller_for_pod(pod_name)
            }
            
            if namespace in namespace_controllers:
                controller = namespace_controllers[namespace]
                if controller:
                    # Validate that this is genuine admission controller activity
                    if self._is_admission_controller_activity(event_data, output_fields):
                        return controller
        
        
        # Method 2: Extract from webhook certificate operations
        if 'webhook-certs' in command or 'admission-controller-certs' in command:
            # Extract controller name from pod UUID in kubelet paths
            import re
            pod_uuid_match = re.search(r'/var/lib/kubelet/pods/([a-f0-9-]{36})/', command)
            if pod_uuid_match:
                pod_uuid = pod_uuid_match.group(1)
                controller_name = self._get_controller_from_pod_uuid(pod_uuid)
                if controller_name:
                    return self._clean_pod_name(controller_name)
            
            # Parse controller name from certificate secret naming patterns
            cert_patterns = [
                r'secret/([^-]+)-webhook-certs',
                r'secret/([^-]+)-certs', 
                r'/([^/]+)-webhook-certs/',
                r'/([^/]+)-certs/'
            ]
            
            for pattern in cert_patterns:
                match = re.search(pattern, command)
                if match:
                    controller_name = match.group(1)
                    if self._is_valid_controller_name(controller_name):
                        return controller_name
        
        # Method 3: Fallback extraction from kubelet pod UUID paths
        if command:
            import re
            # Extract pod UUID from kubelet paths like /var/lib/kubelet/pods/{pod-uuid}/
            pod_uuid_match = re.search(r'/var/lib/kubelet/pods/([a-f0-9-]{36})/', command)
            if pod_uuid_match:
                pod_uuid = pod_uuid_match.group(1)
                controller_name = self._get_controller_from_pod_uuid(pod_uuid)
                if controller_name and self._is_admission_controller_by_behavior(controller_name, event_data):
                    return self._clean_pod_name(controller_name)
        
        # Priority 3: Extract from container context
        container_id = output_fields.get('container.id', '') or event_data.get('container_id', '')
        if container_id:
            controller_name = self._get_controller_from_container_id(container_id)
            if controller_name and self._is_admission_controller_by_behavior(controller_name, event_data):
                return self._clean_pod_name(controller_name)
        
        # Priority 4: Name sources for admission controller indicators
        name_sources = [
            output_fields.get('k8s.pod.name', ''),
            output_fields.get('container.name', ''),
            event_data.get('k8s_pod_name', ''),
            event_data.get('container_name', '')
        ]
        
        for source in name_sources:
            if not source:
                continue
            source_str = str(source).lower()
            
            # Dynamic admission controller detection based on common patterns
            admission_indicators = ['webhook', 'admission', 'controller', 'mutating', 'validating']
            if any(indicator in source_str for indicator in admission_indicators):
                # Additional validation to ensure it's really an admission controller
                if self._validate_admission_controller_context(event_data):
                    return self._clean_pod_name(str(source))
        
        # Priority 5: Process behavior patterns
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        
        # Look for webhook server processes with admission controller behavior
        if proc_name in ['python3', 'python', 'server'] and command:
            # Webhook/admission controller command patterns
            webhook_keywords = ['webhook', 'admission', 'mutating', 'validating', 'server.py', 'controller.py']
            if any(keyword in command.lower() for keyword in webhook_keywords):
                # Extract name from script or process context
                import re
                script_match = re.search(r'/([^/]*(?:webhook|controller|admission)[^/]*\.py)', command)
                if script_match:
                    script_name = script_match.group(1).replace('.py', '')
                    if self._validate_admission_controller_context(event_data):
                        return script_name
        
        # Method 4: Analyze process and command patterns
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        
        # Extract controller names from network tool usage patterns
        if proc_name in ['wget', 'curl'] and command:
            import re
            # Parse controller name from Kubernetes service URL patterns
            service_match = re.search(r'https?://([^.]+)\..*\.svc\.cluster\.local', command)
            if service_match:
                controller_name = service_match.group(1)
                return controller_name
            
            # Fallback to simpler URL pattern matching  
            webhook_match = re.search(r'https?://([^/]+)', command)
            if webhook_match:
                service_url = webhook_match.group(1)
                if any(pattern in service_url for pattern in ['webhook', 'admission', 'controller']):
                    # Extract service name component from URL
                    service_name = service_url.split('.')[0] if '.' in service_url else service_url
                    return service_name
            
            # Generate descriptive names for unidentified webhook activity
            if 'webhook' in command.lower():
                return 'network-webhook-client'
            elif any(pattern in command.lower() for pattern in ['.svc.cluster.local', ':443/', 'https://']):
                return 'suspicious-network-client'
        
        # For suspicious binary execution 
        if 'executing binary not part of base image' in event_data.get('rule', '').lower():
            if proc_name:
                return f'suspicious-{proc_name}'
            else:
                return 'suspicious-binary'
        
        # Extract controller from mount/umount operations
        if proc_name in ['mount', 'umount'] and command:
            import re
            
            # Extract from any admission controller certificate paths
            if 'webhook-certs' in command or '-certs' in command:
                # Try to extract controller name from the certificate path
                cert_match = re.search(r'secret/([^/]+)-certs', command)
                if cert_match:
                    controller_name = cert_match.group(1)
                    # Clean up the controller name
                    if 'webhook' in controller_name:
                        controller_name = controller_name.replace('-webhook', '')
                    return controller_name
                
                # Fallback: Extract pod UUID and map to controller
                pod_uuid_match = re.search(r'/var/lib/kubelet/pods/([a-f0-9-]{36})/', command)
                if pod_uuid_match:
                    pod_uuid = pod_uuid_match.group(1)
                    controller_name = self._get_controller_from_pod_uuid(pod_uuid)
                    if controller_name:
                        return self._clean_pod_name(controller_name)
                # Don't return generic names, filter out
                return None
            
            # For kube-api-access volumes, determine controller
            elif 'kube-api-access' in command:
                pod_uuid_match = re.search(r'/var/lib/kubelet/pods/([a-f0-9-]{36})/', command)
                if pod_uuid_match:
                    pod_uuid = pod_uuid_match.group(1)
                    controller_name = self._get_controller_from_pod_uuid(pod_uuid)
                    if controller_name and self._is_admission_controller_name(controller_name):
                        return self._clean_pod_name(controller_name)  # Same controller, don't add suffix
                # Only return generic api-access-mount if is not possible to identify the specific controller
                # or if it's not a real admission controller
                return None  # Filter out non-admission controller API access mounts
            else:
                # For other mount/umount operations, they're not admission controllers
                return None
        
        # Priority 6: Generic namespace-based controller detection
        container_id = output_fields.get('container.id', '') or event_data.get('container_id', '')
        
        # Generic controller detection from container context
        if container_id:
            controller_name = self._get_controller_from_container_id(container_id)
            if controller_name and self._is_admission_controller_by_behavior(controller_name, event_data):
                return self._clean_pod_name(controller_name)
        
        # No generic fallback - only return actual admission controllers
        return None
    
    def _is_admission_controller_name(self, name: str) -> bool:
        """Check if a name represents an actual admission controller"""
        if not name:
            return False
            
        name_lower = name.lower()
        
        # Known admission controller patterns
        admission_controller_patterns = [
            'webhook', 'admission', 'mutating', 'validating',
            'cert-manager', 'istio-sidecar-injector', 'resource-quota',
            'security-policy-validator', 'controller'
        ]
        
        # Exclude test applications and regular apps
        excluded_patterns = [
            'regular-app', 'test-app', 'app-', 'sidecar-test',
            'demo-', 'example-', 'sample-'
        ]
        
        # Must contain admission controller indicators
        has_admission_pattern = any(pattern in name_lower for pattern in admission_controller_patterns)
        
        # Must not be a test/regular application
        is_excluded = any(pattern in name_lower for pattern in excluded_patterns)
        
        return has_admission_pattern and not is_excluded
    
    def _clean_pod_name(self, pod_name: str) -> str:
        """Clean pod name to extract base controller name"""
        import re
        # Remove common Kubernetes pod name suffixes
        base_name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', pod_name)  # Remove -replicaset-hash-pod-hash
        base_name = re.sub(r'-[a-f0-9]{8,12}$', '', base_name)  # Remove lone replicaset hash
        base_name = re.sub(r'-[0-9]{10,13}-[0-9]{1,5}$', '', base_name)  # Remove timestamp patterns
        return base_name if base_name != pod_name else pod_name
    
    def _extract_namespace_context(self, output_fields: dict, event_data: dict, controller_name: str) -> str:
        """Extract namespace with improved context detection"""
        # Direct fields
        namespace = output_fields.get('k8s.ns.name') or event_data.get('k8s_ns_name')
        if namespace:
            return namespace
        
        # Infer from controller name patterns  
        if any(controller in controller_name.lower() for controller in ['cert-manager', 'istio', 'resource-quota', 'security-policy']):
            return 'baseline-test'  # Known baseline deployment namespace
        elif any(pattern in controller_name.lower() for pattern in ['webhook', 'admission', 'controller']):
            return 'monitoring-system'  # Known malicious deployment namespace
        
        # Command namespace indicators
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        if 'baseline-test' in command:
            return 'baseline-test'
        elif 'monitoring-system' in command:
            return 'monitoring-system'
        elif 'kube-system' in command:
            return 'kube-system'
        
        return 'unknown'
    
    def _extract_pod_context(self, output_fields: dict, event_data: dict, controller_name: str) -> str:
        """Extract pod name with improved context detection"""
        # Direct fields
        pod_name = output_fields.get('k8s.pod.name') or event_data.get('k8s_pod_name')
        if pod_name:
            return pod_name
        
        # Generate likely pod name from controller
        if controller_name and controller_name != 'unknown':
            return f'{controller_name}-pod'
        
        return 'unknown'
    
    def _extract_container_context(self, output_fields: dict, event_data: dict) -> str:
        """Extract container name with improved context detection"""
        # Direct fields  
        container_name = output_fields.get('container.name') or event_data.get('container_name')
        if container_name:
            return container_name
        
        # Use container ID if available
        container_id = output_fields.get('container.id') or event_data.get('container_id')
        if container_id:
            return container_id[:12]  # Short container ID
        
        return 'unknown'
    
    def _is_suspicious_activity_context(self, event_data: Dict, output_fields: Dict) -> bool:
        """Check if event context indicates suspicious admission controller activity"""
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        
        # Detect suspicious activities that may indicate malicious admission controllers
        suspicious_indicators = [
            ('cat', 'serviceaccount/token'),  # Token harvesting
            ('wget', 'kubernetes.default'),   # API reconnaissance 
            ('cat', '/proc/self/status'),     # Capability enumeration
            ('nc', 'kubernetes.default'),     # Network reconnaissance
            ('find', '/var/run'),             # Filesystem reconnaissance
            ('ls', '/proc/1/'),               # Process enumeration
        ]
        
        for proc, cmd_pattern in suspicious_indicators:
            if proc_name == proc and cmd_pattern in command:
                return True
        
        # Suspicious commands from test workloads
        if proc_name in ['cat', 'wget', 'nc', 'find', 'ls'] and any(
            indicator in command.lower() for indicator in [
                'token', 'kubernetes', 'proc/self', 'proc/1', 'var/run', 'api/v1'
            ]
        ):
            return True
            
        return False
    
    def _get_baseline_controller_for_pod(self, pod_name: str) -> Optional[str]:
        """Determine which baseline controller processed this pod based on pod name patterns"""
        pod_lower = pod_name.lower()
        
        # Map pod patterns to baseline controllers
        if 'cert-manager' in pod_lower:
            return 'cert-manager-webhook'
        elif 'istio' in pod_lower:
            return 'istio-sidecar-injector'
        elif 'resource-quota' in pod_lower:
            return 'resource-quota-webhook'
        elif 'security-policy' in pod_lower:
            return 'security-policy-validator'
        
        # For generic pods in baseline-test, assume cert-manager processed them
        return 'cert-manager-webhook'
    
    def _is_admission_controller_activity(self, event_data: Dict, output_fields: Dict) -> bool:
        """Check if this event represents admission controller related activity - BALANCED"""
        # Check for webhook-related activities
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        container_id = output_fields.get('container.id', '')
        container_name = output_fields.get('container.name', '') or event_data.get('container_name', '')
        pod_name = output_fields.get('k8s.pod.name', '') or event_data.get('k8s_pod_name', '')
        
        # If this is a container event with strong webhook/admission names, include it
        if container_id or container_name or pod_name:
            # Check if container/pod has strong admission controller indicators
            combined = f"{container_name} {pod_name}".lower()
            strong_terms = ['webhook', 'admission', 'mutating', 'validating']
            if any(term in combined for term in strong_terms):
                return True
        
        # Specific admission controller activities
        # Webhook server activities with context
        if proc_name in ['python3', 'python'] and ('webhook' in command.lower() or 'admission' in command.lower()):
            return True
            
        # Certificate operations with webhook context
        if proc_name in ['mount', 'umount'] and ('webhook' in command or 'admission' in command):
            return True
            
        # Network operations to webhook ports
        if proc_name in ['wget', 'curl'] and (':8443' in command or ':443' in command or 'webhook' in command):
            return True
        
        # Webhook-specific file operations
        if 'webhook-cert' in command or 'admission-cert' in command:
            return True
            
        return False
    
    def _is_valid_controller_name(self, controller_name: str) -> bool:
        """Check if extracted controller name is valid"""
        if not controller_name or len(controller_name) < 3:
            return False
        
        # Filter out system processes
        system_processes = ['mount', 'umount', 'kubelet', 'dockerd', 'containerd']
        if controller_name.lower() in system_processes:
            return False
            
        return True
    
    def _is_admission_controller_by_behavior(self, controller_name: str, event_data: Dict) -> bool:
        """Check if a controller represents an admission controller based on behavioral patterns - BALANCED"""
        if not controller_name:
            return False
        
        controller_str = controller_name.lower()
        
        # Reject regular app patterns
        reject_patterns = ['regular-app', 'test-app', 'nginx', 'redis', 'mysql', 'postgres', 
                          'busybox', 'alpine', 'ubuntu', 'debian', 'httpd', 'tomcat',
                          'sidecar', 'proxy', 'envoy', 'logging']
        # Note: 'monitoring' removed to allow monitoring-agent malicious controller detection
        for pattern in reject_patterns:
            if pattern in controller_str:
                # Check if it's just a regular app (no admission controller keywords)
                has_admission_keyword = any(indicator in controller_str for indicator in 
                                           ['webhook', 'admission', 'mutating', 'validating'])
                if not has_admission_keyword:
                    return False
                # Even with keywords, be suspicious of test apps
                if 'test' in controller_str or 'regular' in controller_str:
                    return False
        
        # Immediately reject definite system processes
        if controller_str.startswith('system-controller-'):
            output_fields = event_data.get('output_fields', {})
            command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
            proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
            
            definite_system_processes = ['dockerd', 'containerd-shim', 'systemd']
            if any(sys_proc == proc_name for sys_proc in definite_system_processes):
                return False
        
        # Strong admission controller name patterns
        strong_indicators = ['webhook', 'admission', 'mutating', 'validating']
        weak_indicators = ['controller', 'policy', 'security']
        
        has_strong_name = any(indicator in controller_str for indicator in strong_indicators)
        has_weak_name = any(indicator in controller_str for indicator in weak_indicators)
        
        # Admission controller behavioral context  
        has_admission_behavior = self._validate_admission_controller_context(event_data)
        
        # BALANCED: Require strong name OR (weak name AND behavior)
        if has_strong_name:
            return True
        if has_weak_name and has_admission_behavior:
            return True
        
        # Don't accept names without any indicators even with behavior
        if not has_strong_name and not has_weak_name:
            return False
            
        return False
    
    def _validate_admission_controller_context(self, event_data: Dict) -> bool:
        """Validate that event context indicates admission controller infrastructure activity - RELAXED"""
        output_fields = event_data.get('output_fields', {})
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        container_name = output_fields.get('container.name', '') or event_data.get('container_name', '')
        pod_name = output_fields.get('k8s.pod.name', '') or event_data.get('k8s_pod_name', '')
        
        # Exclude only core system processes that are definitely not admission controllers
        system_processes_to_exclude = [
            'dockerd' in command and '--default-ulimit' in command,
            'containerd' in command and 'io.containerd' in command,
            'kubelet' in command and '--kubeconfig' in command,
            'kube-proxy' in command,
            'etcd' in command and '--data-dir' in command,
        ]
        
        if any(system_processes_to_exclude):
            return False
        
        # Balanced admission controller indicators
        admission_controller_infrastructure = [
            # Strong webhook or admission related terms in command or container
            'webhook' in command.lower() or 'webhook' in str(container_name).lower() or 'webhook' in str(pod_name).lower(),
            'admission' in command.lower() or 'admission' in str(container_name).lower() or 'admission' in str(pod_name).lower(),
            'mutating' in command.lower() or 'validating' in command.lower(),
            
            # Webhook/controller scripts specifically
            'webhook.py' in command.lower() or 'controller.py' in command.lower(),
            
            # Certificate operations with webhook context
            'webhook-cert' in command or 'admission-cert' in command,
            
            # Python processes ONLY in webhook/admission containers
            proc_name in ['python3', 'python'] and any(term in str(container_name).lower() for term in ['webhook', 'admission', 'mutating', 'validating']),
            
            # Mount operations specifically for webhook certificates
            proc_name in ['mount', 'umount'] and ('webhook' in command or 'admission' in command),
            
            # Network operations to webhook endpoints
            proc_name in ['wget', 'curl'] and ('webhook' in command or 'admission' in command or ':8443' in command),
        ]
        
        # Return true if ANY pattern matches (more permissive)
        return any(admission_controller_infrastructure)
    
    def _has_admin_context(self, event_data: Dict) -> bool:
        """Check if the event has administrative/privileged context"""
        output_fields = event_data.get('output_fields', {})
        
        # Admin user context
        user_uid = output_fields.get('user.uid', 0) or event_data.get('user_uid', 0)
        if user_uid == 0:  # root user
            return True
        
        # Privileged process capabilities
        proc_name = output_fields.get('proc.name', '') or event_data.get('proc_name', '')
        admin_processes = ['python3', 'python', 'controller', 'webhook', 'server']
        if proc_name in admin_processes:
            return True
        
        # System-level file access patterns
        command = output_fields.get('proc.cmdline', '') or event_data.get('proc_cmdline', '')
        system_paths = ['/var/lib/kubelet', '/etc/kubernetes', '/host', '/sys', '/proc']
        if any(path in command for path in system_paths):
            return True
        
        return False
    
    def _get_controller_from_pod_uuid(self, pod_uuid: str) -> Optional[str]:
        """Get controller name from pod UUID by querying Kubernetes API"""
        try:
            import subprocess
            # Get pod info using the UUID from all namespaces
            result = subprocess.run([
                'kubectl', 'get', 'pods', '--all-namespaces', 
                '-o', f'jsonpath={{.items[?(@.metadata.uid=="{pod_uuid}")].metadata.name}}'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                pod_name = result.stdout.strip()
                # Extract controller name from pod name (remove random suffix)
                import re
                # Remove common Kubernetes pod name suffixes
                # Pattern: deployment-name-replicaset-hash-pod-hash  
                controller_name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', pod_name)  # Remove -replicaset-hash-pod-hash (hex-base32)
                controller_name = re.sub(r'-[a-f0-9]{8,12}$', '', controller_name)  # Remove lone replicaset hash
                controller_name = re.sub(r'-[0-9]{10,13}-[0-9]{1,5}$', '', controller_name)  # Remove timestamp patterns
                return controller_name if controller_name != pod_name else pod_name
        except:
            pass
        return None
    
    def _get_controller_from_container_id(self, container_id: str) -> Optional[str]:
        """Get controller name from container ID"""
        try:
            import subprocess
            # Get container info to find associated pod
            result = subprocess.run([
                'kubectl', 'get', 'pods', '--all-namespaces',
                '-o', f'jsonpath={{.items[?(@.status.containerStatuses[*].containerID=~".*{container_id}")].metadata.name}}'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                pod_name = result.stdout.strip()
                # Extract controller name from pod name
                import re
                # Remove common Kubernetes pod name suffixes
                controller_name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', pod_name)  # Remove -replicaset-hash-pod-hash (hex-base32)
                controller_name = re.sub(r'-[a-f0-9]{8,12}$', '', controller_name)  # Remove lone replicaset hash
                controller_name = re.sub(r'-[0-9]{10,13}-[0-9]{1,5}$', '', controller_name)  # Remove timestamp patterns
                return controller_name if controller_name != pod_name else pod_name
            else:
                # No fallback - only return actual admission controllers
                return None
        except:
            pass
        return None
    
    def _get_deployed_admission_controllers(self) -> List[str]:
        """Dynamically get list of currently deployed admission controllers"""
        try:
            import subprocess
            result = subprocess.run(['kubectl', 'get', 'deployments', '--all-namespaces', '-o', 'jsonpath={.items[*].metadata.name}'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                deployments = result.stdout.strip().split()
                # Filter for admission controller deployments
                controllers = [dep for dep in deployments if any(keyword in dep.lower() for keyword in ['webhook', 'admission', 'controller', 'injector', 'validator'])]
                return controllers if controllers else ['unknown-controller']
        except:
            pass
        
        # Default if kubectl fails
        return ['unknown-controller']
    
    def _extract_host_mounts(self, event_data: Dict) -> List[str]:
        """Extract host mount information from event"""
        mounts = []
        
        # Host filesystem access patterns
        fd_name = event_data.get('fd_name', '')
        if fd_name and any(path in fd_name for path in ['/host', '/proc', '/sys', '/dev']):
            mounts.append(fd_name)
        
        return mounts
    
    def _detect_network_activity(self, event_data: Dict) -> bool:
        """Detect network activity in Falco event"""
        network_indicators = [
            'socket', 'connect', 'bind', 'listen', 'accept',
            'http', 'https', 'tcp', 'udp', 'wget', 'curl'
        ]
        
        # Top level and output_fields for Falco compatibility
        output_fields = event_data.get('output_fields', {})
        check_fields = [
            event_data.get('fd_name', ''),
            event_data.get('fd_type', ''),
            event_data.get('evt_type', ''),
            event_data.get('proc_cmdline', ''),
            str(output_fields.get('proc.cmdline', '')),
            str(output_fields.get('proc.name', '')),
            str(output_fields.get('fd.name', ''))
        ]
        
        combined_text = ' '.join(check_fields).lower()
        
        return any(indicator in combined_text for indicator in network_indicators)
    
    def _count_file_operations(self, event_data: Dict) -> int:
        """Count file operations from event data"""
        file_ops = 0
        
        # Count based on event type
        evt_type = event_data.get('evt_type', '')
        if evt_type in ['open', 'openat', 'read', 'write', 'close']:
            file_ops += 1
        
        # Count based on file descriptor activity
        if event_data.get('fd_name'):
            file_ops += 1
        
        return file_ops
    
    def _core_admission_controller_features(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract Core Admission Controller Features (8 features)
        
        These features identify admission controller specific behaviors:
        - Webhook type (mutating vs validating)
        - Port usage (standard webhook ports)
        - TLS certificate handling
        - AdmissionReview API processing
        - Kubernetes API interactions
        """
        # Determine if this is a mutating or validating webhook
        webhook_mutating = int('mutating' in event.admission_controller_name.lower() or 'mutate' in event.command.lower())
        webhook_validating = int('validating' in event.admission_controller_name.lower() or 'validate' in event.command.lower())
        
        # Dynamic port detection for webhook services
        import re
        port_pattern = r':(\d+)'
        ports = re.findall(port_pattern, event.command or '')
        webhook_port_standard = int(bool([p for p in ports if p.isdigit() and int(p) > 1024]))
        
        webhook_tls_cert = int('cert' in event.command.lower() or 'tls' in event.command.lower() or '/etc/certs' in event.command)
        webhook_config_mount = int('/etc/webhook' in event.command or 'configmap' in event.command.lower())
        admission_review_processing = int('admissionreview' in event.command.lower() or 'admission' in event.process_name.lower())
        webhook_server_running = int('webhook' in event.process_name.lower() or 'server' in event.process_name.lower())
        kubernetes_api_calls = int('kubernetes' in event.command.lower() or 'kubectl' in event.command.lower())
        
        return {
            'webhook_mutating': webhook_mutating,
            'webhook_validating': webhook_validating,
            'webhook_port_standard': webhook_port_standard,
            'webhook_tls_cert': webhook_tls_cert,
            'webhook_config_mount': webhook_config_mount,
            'admission_review_processing': admission_review_processing,
            'webhook_server_running': webhook_server_running,
            'kubernetes_api_calls': kubernetes_api_calls,
        }
    
    def _process_indicators(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract Process Indicators (6 features)
        
        These features capture process-level behaviors that may indicate
        malicious activity:
        - Privileged execution
        - Linux capabilities
        - Suspicious commands (curl, wget, netcat)
        - Shell activity
        """
        process_privileged = int(event.privileged)
        process_capabilities = len(event.capabilities)
        # Replace command length with process execution patterns (more meaningful for admission controllers)
        process_execution_anomaly = int(event.process_name in ['python3', 'python'] and 'webhook' not in event.command.lower())
        process_suspicious_commands = int(any(cmd in event.command.lower() for cmd in ['curl', 'wget', 'nc', 'bash', 'sh', '/bin/sh']))
        process_network_tools = int(any(tool in event.command.lower() for tool in ['nmap', 'netcat', 'telnet', 'ssh']))
        process_shell_activity = int(any(shell in event.process_name.lower() for shell in ['bash', 'sh', 'zsh', 'fish']))
        
        return {
            'process_privileged': process_privileged,
            'process_capabilities': process_capabilities,
            'process_execution_anomaly': process_execution_anomaly,
            'process_suspicious_commands': process_suspicious_commands,
            'process_network_tools': process_network_tools,
            'process_shell_activity': process_shell_activity,
        }
    
    def _file_access_indicators(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract File Access Indicators (7 features)
        
        These features detect suspicious file system activity:
        - Access to sensitive files (/etc/passwd, /etc/shadow)
        - Configuration file modifications
        - Certificate file operations
        - Container escape attempts
        - Kubernetes secrets access
        """
        sensitive_file_access = int(any(path in event.command for path in ['/etc/passwd', '/etc/shadow', '/root']))
        config_file_modification = int('/etc/' in event.command and any(action in event.command.lower() for action in ['write', 'modify', 'edit']))
        certificate_file_access = int(any(cert_path in event.command for cert_path in ['/etc/ssl', '/etc/pki', '.crt', '.key', '.pem']))
        host_filesystem_mount = len(event.host_mounts)
        container_escape_attempt = int(any(escape_path in event.command for escape_path in ['/proc/1/', '/host', '/var/run/docker.sock']))
        log_file_access = int(any(log_path in event.command for log_path in ['/var/log', '.log', 'journalctl']))
        kubernetes_secrets_access = int('secret' in event.command.lower() and ('get' in event.command.lower() or 'read' in event.command.lower()))
        
        return {
            'sensitive_file_access': sensitive_file_access,
            'config_file_modification': config_file_modification,
            'certificate_file_access': certificate_file_access,
            'host_filesystem_mount': host_filesystem_mount,
            'container_escape_attempt': container_escape_attempt,
            'log_file_access': log_file_access,
            'kubernetes_secrets_access': kubernetes_secrets_access,
        }
    
    def _network_behavior_features(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract Network Behavior (5 features)
        
        These features identify network-related activities:
        - Outbound connections
        - Suspicious domain access
        - Port scanning
        - DNS resolution anomalies
        """
        network_activity_detected = int(event.network_activity)
        outbound_connections = int('connect' in event.command.lower() or 'http' in event.command.lower())
        suspicious_domains = int(any(domain in event.command.lower() for domain in ['pastebin', 'githubusercontent', 'bit.ly', 'tinyurl']))
        port_scanning_activity = int('nmap' in event.command.lower() or 'masscan' in event.command.lower())
        dns_resolution_anomaly = int('nslookup' in event.command.lower() or 'dig' in event.command.lower())
        
        return {
            'network_activity_detected': network_activity_detected,
            'outbound_connections': outbound_connections,
            'suspicious_domains': suspicious_domains,
            'port_scanning_activity': port_scanning_activity,
            'dns_resolution_anomaly': dns_resolution_anomaly,
        }
    
    def _container_indicators(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract Container Indicators (6 features)
        
        These features capture container-specific security risks:
        - Privileged containers
        - Container runtime access
        - Host network/PID namespace sharing
        - Volume mounts from host
        - Environment variable usage
        """
        process_privileged = int(event.privileged)
        container_runtime_access = int('docker' in event.command.lower() or 'containerd' in event.command.lower())
        container_privileged_escalation = int(process_privileged and len(event.capabilities) > 2)
        container_host_network = int('hostNetwork' in event.command or 'host' in event.namespace.lower())
        container_pid_namespace = int('hostPID' in event.command or 'pid' in event.command.lower())
        container_volume_mounts = len(event.host_mounts)
        container_environment_vars = len(event.env_vars)
        
        return {
            'container_runtime_access': container_runtime_access,
            'container_privileged_escalation': container_privileged_escalation,
            'container_host_network': container_host_network,
            'container_pid_namespace': container_pid_namespace,
            'container_volume_mounts': container_volume_mounts,
            'container_environment_vars': container_environment_vars,
        }
    
    def _kubernetes_context_features(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract Kubernetes Context (5 features)"""
        namespace_system = int(event.namespace in ['kube-system', 'kube-public', 'default'])
        pod_security_context = int('securityContext' in event.command or 'runAsRoot' in event.command)
        service_account_usage = int('serviceaccount' in event.command.lower() or 'token' in event.command.lower())
        rbac_permissions = int('rbac' in event.command.lower() or 'clusterrole' in event.command.lower())
        api_server_communication = int('apiserver' in event.command.lower() or '6443' in event.command)
        
        return {
            'namespace_system': namespace_system,
            'pod_security_context': pod_security_context,
            'service_account_usage': service_account_usage,
            'rbac_permissions': rbac_permissions,
            'api_server_communication': api_server_communication,
        }
    
    def _security_violations(self, event: AdmissionControllerEvent) -> Dict[str, int]:
        """Extract Security Violations (3 features)"""
        process_privileged = int(event.privileged)
        privilege_escalation_detected = int(process_privileged and any(cap in ['SYS_ADMIN', 'NET_ADMIN', 'DAC_OVERRIDE'] for cap in event.capabilities))
        
        # Enhanced suspicious binary execution detection using Falco rule patterns
        critical_falco_rules = [
            'drop and execute new binary in container',
            'executing binary not part of base image',
            'redirect stdout/stdin to network connection',
            'contact k8s api server from container',
            'write below etc',
            'sensitive mount by container',
            'access sensitive files',
        ]
        
        # Check if event triggered critical security violations
        rule_based_detection = 0
        if hasattr(event, 'rule') and event.rule:
            rule_lower = event.rule.lower()
            rule_based_detection = int(any(critical_rule in rule_lower for critical_rule in critical_falco_rules))
        
        # Process-based detection (fallback)
        process_based_detection = int(any(binary in event.process_name.lower() for binary in ['nc', 'ncat', 'socat', 'python', 'perl', 'ruby']))
        
        # Use rule-based detection as primary indicator, process-based as secondary
        suspicious_binary_execution = max(rule_based_detection, process_based_detection)
        
        anomalous_file_operations = event.file_operations
        
        return {
            'privilege_escalation_detected': privilege_escalation_detected,
            'suspicious_binary_execution': suspicious_binary_execution,
            'anomalous_file_operations': anomalous_file_operations,
        }
    
    def _threat_indicators(self, event: AdmissionControllerEvent) -> Dict[str, float]:
        """Extract Threat Indicators (3 features)"""
        persistence_mechanism = int(any(persist in event.command.lower() for persist in ['crontab', 'systemd', 'service', 'daemon']))
        
        # Enhanced data exfiltration detection using Falco rules and command patterns
        exfil_rule_patterns = [
            'redirect stdout/stdin to network connection',
            'contact k8s api server from container',
            'network connection outside cluster',
        ]
        
        # Check rule-based data exfiltration indicators
        rule_based_exfiltration = 0
        if hasattr(event, 'rule') and event.rule:
            rule_lower = event.rule.lower()
            rule_based_exfiltration = int(any(pattern in rule_lower for pattern in exfil_rule_patterns))
        
        # Command-based data exfiltration indicators
        command_based_exfiltration = int(any(exfil in event.command.lower() for exfil in ['base64', 'gzip', 'tar', 'zip', 'wget', 'curl', 'nc ', 'cat /var/run/secrets']))
        
        data_exfiltration_signs = max(rule_based_exfiltration, command_based_exfiltration)
        command_obfuscation = self._calculate_entropy(event.command)
        
        return {
            'persistence_mechanism': persistence_mechanism,
            'data_exfiltration_signs': data_exfiltration_signs,
            'command_obfuscation': command_obfuscation,
        }
    
    def _extract_ml_features(self, events: List[AdmissionControllerEvent]) -> pd.DataFrame:
        """Extract 43 behavioral features from admission controller events for ML classification
        
        Features are grouped into 7 categories:
        1. Core Admission Features (8): webhook type, ports, TLS, API calls
        2. Process Indicators (6): privileges, capabilities, command patterns
        3. File Access (7): sensitive files, configs, certificates, secrets
        4. Network Behavior (5): connections, domains, port scanning
        5. Container Context (6): runtime access, namespaces, volumes
        6. Kubernetes Context (5): namespace, RBAC, service accounts
        7. Security Violations (3): privilege escalation, suspicious binaries
        8. Threat Indicators (3): persistence, exfiltration, command entropy
        
        Args:
            events: List of parsed admission controller events
            
        Returns:
            DataFrame with 43 features for each event
        """
        """Extract 43 admission controller-specific ML features from events"""
        features = []
        
        for event in events:
            # Extract features using helper methods
            feature_vector = {}
            
            # Core Admission Controller Features (8)
            feature_vector.update(self._core_admission_controller_features(event))
            
            # Process Indicators (6)
            feature_vector.update(self._process_indicators(event))
            
            # File Access Indicators (7)
            feature_vector.update(self._file_access_indicators(event))
            
            # Network Behavior (5)
            feature_vector.update(self._network_behavior_features(event))
            
            # Container Indicators (6)
            feature_vector.update(self._container_indicators(event))
            
            # Kubernetes Context (5)
            feature_vector.update(self._kubernetes_context_features(event))
            
            # Security Violations (3)
            feature_vector.update(self._security_violations(event))
            
            # Threat Indicators (3)
            feature_vector.update(self._threat_indicators(event))
            
            features.append(feature_vector)
        
        df = pd.DataFrame(features)
        self.feature_names = list(df.columns)
        
        logger.info(f"Extracted {len(self.feature_names)} ML features from {len(events)} events")
        return df
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        import collections
        counts = collections.Counter(text)
        probabilities = [count / len(text) for count in counts.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy
    
    def _generate_risk_labels(self, events: List[AdmissionControllerEvent], features_df: pd.DataFrame) -> List[str]:
        """Generate risk labels based on behavioral indicators"""
        labels = []
        
        for i, event in enumerate(events):
            risk_indicators = 0
            
            # Risk factors
            if event.privileged:
                risk_indicators += 2
            
            if len(event.capabilities) > 3:
                risk_indicators += 2
            
            if len(event.host_mounts) > 0:
                risk_indicators += 1
            
            if event.network_activity and 'curl' in event.command.lower():
                risk_indicators += 1
            
            if any(suspicious in event.command.lower() for suspicious in ['wget', 'nc', 'bash', 'sh']):
                risk_indicators += 1
            
            # Classify based on risk indicators
            if risk_indicators >= 4:
                labels.append('MALICIOUS')
            elif risk_indicators >= 2:
                labels.append('SUSPICIOUS')
            else:
                labels.append('LEGITIMATE')
        
        return labels
    
    def _calculate_risk_score(self, rf_prob: np.ndarray, anomaly_score: float, event: AdmissionControllerEvent = None) -> float:
        """Calculate combined risk score from Random Forest and Isolation Forest with rule-based boost"""
        # Convert anomaly score to probability (Isolation Forest returns negative values)
        anomaly_prob = max(0, min(1, (anomaly_score + 0.5) / 1.0))
        
        # Get malicious probability from Random Forest
        if len(rf_prob) > 2:  # LEGITIMATE, SUSPICIOUS, MALICIOUS
            malicious_prob = rf_prob[2]  # MALICIOUS probability
            suspicious_prob = rf_prob[1]  # SUSPICIOUS probability
            rf_risk = malicious_prob + 0.5 * suspicious_prob
        else:
            rf_risk = 1 - rf_prob[0] if len(rf_prob) > 1 else 0.5
        
        # Combine scores (weighted average)
        base_risk_score = 0.7 * rf_risk + 0.3 * (1 - anomaly_prob)
        
        # Apply critical rule boost if event contains high-risk Falco rules
        critical_rule_boost = 0.0
        if event and hasattr(event, 'rule') and event.rule:
            critical_falco_rules = [
                'drop and execute new binary in container',
                'executing binary not part of base image',
                'redirect stdout/stdin to network connection',
                'contact k8s api server from container',
                'write below etc',
                'sensitive mount by container',
                'access sensitive files',
            ]
            
            rule_lower = event.rule.lower()
            if any(critical_rule in rule_lower for critical_rule in critical_falco_rules):
                critical_rule_boost = 0.2  # Boost by 20% for critical security violations
        
        # Apply boost but cap at 1.0
        final_risk_score = min(1.0, base_risk_score + critical_rule_boost)
        return max(0.0, final_risk_score)
    
    def _classify_risk(self, risk_score: float) -> str:
        """Classify risk score into threat level"""
        if risk_score >= self.RISK_THRESHOLD_MALICIOUS:
            return "MALICIOUS"
        elif risk_score >= self.RISK_THRESHOLD_SUSPICIOUS:
            return "SUSPICIOUS"
        else:
            return "LEGITIMATE"
    
    def _generate_behavioral_signature(self, features: dict) -> str:
        """Generate a behavioral signature from features for pattern matching"""
        sig_components = []
        
        # Key behavioral indicators
        if features.get('privileged_execution', 0) > 0:
            sig_components.append('PRIV')
        if features.get('sensitive_file_access', 0) > 0:
            sig_components.append('SENSITIVE_FILES')
        if features.get('network_activity', 0) > 0:
            sig_components.append('NETWORK')
        if features.get('command_entropy', 0) > 4.5:
            sig_components.append('HIGH_ENTROPY')
        if features.get('suspicious_binary_execution', 0) > 0:
            sig_components.append('SUSPICIOUS_BIN')
        if features.get('webhook_server_running', 0) > 0:
            sig_components.append('WEBHOOK_SERVER')
        if features.get('tls_cert_handling', 0) > 0:
            sig_components.append('TLS_CERTS')
            
        return '_'.join(sig_components) if sig_components else 'NORMAL'
    
    def _update_behavioral_profile(self, controller_name: str, features: dict, risk_score: float):
        """Update behavioral profile for a controller"""
        # Use a separate connection with timeout to avoid locks
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")  # Use Write-Ahead Logging to reduce locks
        cursor = conn.cursor()
        
        try:
            # Check if profile exists
            cursor.execute("""
                SELECT id, event_count, entropy_baseline, typical_risk_score
                FROM controller_behavioral_profiles
                WHERE controller_name = ?
            """, (controller_name,))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing profile with running averages
                profile_id, count, old_entropy, old_risk = existing
                new_count = count + 1
                
                # Update running averages
                new_entropy = ((old_entropy or 0) * count + features.get('command_entropy', 0)) / new_count
                new_risk = ((old_risk or 0) * count + risk_score) / new_count
                
                cursor.execute("""
                    UPDATE controller_behavioral_profiles
                    SET event_count = ?, entropy_baseline = ?, typical_risk_score = ?,
                        last_updated = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_count, new_entropy, new_risk, profile_id))
            else:
                # Create new profile
                controller_type = self._determine_controller_type(controller_name)
                cursor.execute("""
                    INSERT INTO controller_behavioral_profiles (
                        controller_name, controller_type, entropy_baseline,
                        typical_risk_score, event_count
                    ) VALUES (?, ?, ?, ?, 1)
                """, (controller_name, controller_type,
                      features.get('command_entropy', 0), risk_score))
                      
            conn.commit()
        except sqlite3.Error as e:
            logger.warning(f"Failed to update behavioral profile: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def _determine_controller_type(self, name: str) -> str:
        """Categorize controller into types for behavioral grouping"""
        name_lower = name.lower()
        if 'cert' in name_lower:
            return 'certificate-manager'
        elif 'istio' in name_lower or 'sidecar' in name_lower:
            return 'sidecar-injector'
        elif 'quota' in name_lower or 'resource' in name_lower:
            return 'resource-manager'
        elif 'security' in name_lower or 'policy' in name_lower:
            return 'policy-validator'
        elif 'mutating' in name_lower:
            return 'mutating-webhook'
        elif 'validating' in name_lower:
            return 'validating-webhook'
        else:
            return 'custom-webhook'
    
    def _apply_behavioral_adjustments(self, features: dict, controller_name: str,
                                     typical_risk: float, typical_entropy: float) -> dict:
        """Adjust features based on behavioral profile for better classification"""
        adjusted = features.copy()
        
        # Normalize entropy based on controller's baseline
        if 'command_entropy' in adjusted and typical_entropy is not None and typical_entropy > 0:
            # If entropy is within normal range for this controller, reduce its impact
            entropy_diff = abs(adjusted['command_entropy'] - typical_entropy)
            if entropy_diff < 1.0:  # Within 1 point of typical
                adjusted['command_entropy'] = adjusted['command_entropy'] * 0.5
                
        # Adjust suspicious binary flag based on controller patterns
        if controller_name and 'python' in controller_name.lower():
            # Python is expected for Python-based controllers
            adjusted['suspicious_binary_execution'] = 0
            
        # Don't add new features during retraining - just adjust existing ones
        # This maintains feature consistency with the original classifier
        
        return adjusted
    
    def _apply_feedback_overrides(self, events: List[AdmissionControllerEvent]) -> List[AdmissionControllerEvent]:
        """Apply analyst feedback overrides to event classifications"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all feedback overrides
        cursor.execute("""
            SELECT admission_controller_name, corrected_classification 
            FROM ml_feedback_overrides
        """)
        
        feedback_overrides = dict(cursor.fetchall())
        conn.close()
        
        if not feedback_overrides:
            return events
        
        # Apply overrides to matching events
        modified_count = 0
        for event in events:
            if event.admission_controller_name in feedback_overrides:
                original_classification = event.classification
                new_classification = feedback_overrides[event.admission_controller_name]
                event.classification = new_classification
                
                # Recalculate risk score based on corrected classification using classifier if available
                if hasattr(self, 'random_forest') and self.random_forest is not None:
                    # Extract features for this event
                    try:
                        features_df = self._extract_ml_features([event])
                        if not features_df.empty:
                            X = self.scaler.transform(features_df.values)
                            
                            # Get probability from Random Forest
                            rf_proba = self.random_forest.predict_proba(X)[0]
                            # Map to risk score based on classification probabilities
                            if new_classification == "LEGITIMATE":
                                # Use legitimate class probability inverted as risk
                                event.risk_score = max(0.1, 1.0 - rf_proba[0]) * 0.4  # Scale to < 0.4
                            elif new_classification == "SUSPICIOUS":
                                # Use suspicious class probability
                                event.risk_score = 0.4 + (rf_proba[1] if len(rf_proba) > 1 else 0.5) * 0.3  # Scale to 0.4-0.7
                            elif new_classification == "MALICIOUS":
                                # Use malicious class probability
                                event.risk_score = 0.7 + (rf_proba[2] if len(rf_proba) > 2 else rf_proba[-1]) * 0.3  # Scale to 0.7-1.0
                        else:
                            # Fallback to reasonable defaults if feature extraction fails
                            if new_classification == "LEGITIMATE":
                                event.risk_score = 0.2
                            elif new_classification == "SUSPICIOUS":
                                event.risk_score = 0.5
                            elif new_classification == "MALICIOUS":
                                event.risk_score = 0.8
                    except Exception as e:
                        logger.debug(f"Could not recalculate risk score: {e}")
                        # Fallback to reasonable defaults
                        if new_classification == "LEGITIMATE":
                            event.risk_score = 0.2
                        elif new_classification == "SUSPICIOUS":
                            event.risk_score = 0.5
                        elif new_classification == "MALICIOUS":
                            event.risk_score = 0.8
                else:
                    # No classifier available, use reasonable defaults
                    if new_classification == "LEGITIMATE":
                        event.risk_score = 0.2
                    elif new_classification == "SUSPICIOUS":
                        event.risk_score = 0.5
                    elif new_classification == "MALICIOUS":
                        event.risk_score = 0.8
                
                if original_classification != event.classification:
                    modified_count += 1
        
        if modified_count > 0:
            logger.info(f"Applied feedback overrides to {modified_count} events across {len(feedback_overrides)} controllers")
        
        return events
    
    def _save_models(self):
        """Save trained classifiers"""
        models = {
            'random_forest': self.random_forest,
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        joblib.dump(models, self.classifier_path)
        logger.info(f"Classifiers saved to {self.classifier_path}")
    
    def _load_models(self):
        """Load trained classifiers"""
        if not self.classifier_path.exists():
            logger.warning("No trained classifiers found")
            return False
        
        try:
            models = joblib.load(self.classifier_path)
            self.random_forest = models['random_forest']
            self.isolation_forest = models['isolation_forest']
            self.scaler = models['scaler']
            self.feature_names = models['feature_names']
            logger.info("Classifiers loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to load classifiers: {e}")
            return False
    
    def _retrain_models_with_feedback(self) -> bool:
        """Retrain classifiers using corrected classifications with full behavioral context"""
        try:
            logger.info("Starting classifier retraining with behavioral feedback...")
            
            # Load existing classifiers if available
            if not self._load_models():
                logger.warning("No existing classifiers found, cannot retrain")
                return False
            
            # Get all events from database with full context and corrected classifications
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Prioritize events with full context for better retraining
            cursor.execute("""
                SELECT 
                    d.timestamp, d.admission_controller_name, d.namespace, d.pod_name, d.container_name,
                    d.image, d.process_name, d.command, d.privileged, d.capabilities, d.host_mounts,
                    d.env_vars, d.network_activity, d.file_operations, d.syscall_frequency,
                    COALESCE(f.corrected_classification, d.classification) as final_classification,
                    d.risk_score, d.confidence,
                    d.full_falco_event, d.extracted_features_json, d.behavioral_signature,
                    p.typical_risk_score, p.entropy_baseline
                FROM ml_detections d
                LEFT JOIN ml_feedback_overrides f ON d.admission_controller_name = f.admission_controller_name
                LEFT JOIN controller_behavioral_profiles p ON d.admission_controller_name = p.controller_name
                WHERE d.classification IS NOT NULL
                ORDER BY d.full_falco_event IS NOT NULL DESC, d.timestamp
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            if len(rows) < 10:  # Need minimum data for meaningful retraining
                logger.warning(f"Insufficient data for retraining: {len(rows)} events")
                return False
            
            # Convert database rows back to AdmissionControllerEvent objects
            events = []
            for row in rows:
                try:
                    capabilities = json.loads(row[9]) if row[9] else []
                    host_mounts = json.loads(row[10]) if row[10] else []
                    env_vars = json.loads(row[11]) if row[11] else {}
                    
                    # Create event with proper field ordering for dataclass
                    event = AdmissionControllerEvent(
                        timestamp=row[0] or "",
                        admission_controller_name=row[1] or "unknown",
                        namespace=row[2] or "default",
                        pod_name=row[3] or "unknown",
                        container_name=row[4] or "unknown",
                        image=row[5] or "unknown",
                        process_name=row[6] or "unknown",
                        command=row[7] or "",
                        rule="Unknown Rule",  # Default value since rule is not in database
                        privileged=bool(row[8]),
                        capabilities=capabilities,
                        host_mounts=host_mounts,
                        env_vars=env_vars,
                        network_activity=bool(row[12]),
                        file_operations=int(row[13]) if row[13] else 0,
                        syscall_frequency=float(row[14]) if row[14] else 0.0,
                        classification=row[15],  # This contains the corrected classification
                        risk_score=float(row[16]) if row[16] else 0.0,
                        confidence=float(row[17]) if row[17] else 0.0
                    )
                    events.append(event)
                except (json.JSONDecodeError, ValueError, TypeError) as e:
                    logger.debug(f"Skipping malformed event: {e}")
                    continue
            
            if not events:
                logger.warning("No valid events found for retraining")
                return False
            
            logger.info(f"Retraining with {len(events)} events and corrected classifications")
            
            # Build feature matrix - prefer stored features for accuracy
            X_list = []
            y = []
            
            for i, event in enumerate(events):
                row = rows[i]
                # Try to use stored features first (more accurate)
                if row[19]:  # extracted_features_json column
                    try:
                        stored_features = json.loads(row[19])
                        # Apply behavioral adjustments based on profile
                        if row[21] is not None:  # typical_risk_score from profile
                            stored_features = self._apply_behavioral_adjustments(
                                stored_features, event.admission_controller_name,
                                row[21], row[22]  # typical_risk, entropy_baseline
                            )
                        X_list.append(list(stored_features.values()))
                    except:
                        # Fallback to extracting features
                        features_df = self._extract_ml_features([event])
                        X_list.append(features_df.values[0])
                else:
                    # Extract features if not stored
                    features_df = self._extract_ml_features([event])
                    X_list.append(features_df.values[0])
                
                # Use corrected classification
                y.append(row[15])  # final_classification column
            
            X = np.array(X_list)
            
            # Ensure we have the required feature consistency
            if hasattr(self, 'feature_names'):
                # Get expected feature count from first row
                if X_list and len(self.feature_names) != len(X_list[0]):
                    logger.error(f"Feature mismatch: expected {len(self.feature_names)}, got {len(X_list[0])}")
                    return False
            
            # Retrain scaler with all data first
            X_scaled = self.scaler.fit_transform(X)
            
            # Retrain Random Forest classifier with corrected labels on scaled data
            logger.info("Retraining Random Forest classifier...")
            self.random_forest = RandomForestClassifier(n_estimators=self.RANDOM_FOREST_ESTIMATORS, random_state=42)
            self.random_forest.fit(X_scaled, y)
            
            # Retrain Isolation Forest for anomaly detection on scaled data (unsupervised)
            logger.info("Retraining Isolation Forest...")
            self.isolation_forest = IsolationForest(contamination=self.ISOLATION_FOREST_CONTAMINATION, random_state=42)
            self.isolation_forest.fit(X_scaled)
            
            # Save updated classifiers
            self._save_models()
            
            # Update database with new predictions for all events
            self._update_predictions_after_retraining(events, X_scaled)
            
            logger.info("Classifier retraining completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Classifier retraining failed: {e}")
            return False
    
    def _update_predictions_after_retraining(self, events: List[AdmissionControllerEvent], X_scaled: np.ndarray):
        """Update risk scores and confidence after classifier retraining"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for i, event in enumerate(events):
                feature_vector = X_scaled[i:i+1]
                
                # Get new predictions from retrained classifiers
                rf_prob = self.random_forest.predict_proba(feature_vector)[0]
                anomaly_score = self.isolation_forest.decision_function(feature_vector)[0]
                
                # Calculate updated risk score (but keep corrected classification)
                new_risk_score = self._calculate_risk_score(rf_prob, anomaly_score, event)
                new_confidence = max(rf_prob)
                
                # Update only risk_score and confidence, preserve corrected classification
                cursor.execute("""
                    UPDATE ml_detections
                    SET risk_score = ?, confidence = ?
                    WHERE admission_controller_name = ? AND timestamp = ?
                """, (new_risk_score, new_confidence, event.admission_controller_name, event.timestamp))
            
            conn.commit()
            conn.close()
            logger.info("Updated risk scores and confidence after retraining")
            
        except Exception as e:
            logger.error(f"Failed to update predictions after retraining: {e}")
    
    def _store_events_with_context(self, events: List[AdmissionControllerEvent], falco_events: List[dict] = None):
        """Store classified events with full Falco context for behavioral learning"""
        # Use connection with timeout and WAL mode to avoid locks
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        for i, event in enumerate(events):
            # Get corresponding Falco event if available
            falco_event = falco_events[i] if falco_events and i < len(falco_events) else None
            
            # Extract all features for this event to store
            features_df = self._extract_ml_features([event])
            features_dict = features_df.iloc[0].to_dict() if not features_df.empty else {}
            
            # Generate behavioral signature
            behavioral_sig = self._generate_behavioral_signature(features_dict)
            
            # Store in main ml_detections table with full context
            cursor.execute("""
                INSERT INTO ml_detections (
                    timestamp, admission_controller_name, namespace, pod_name, container_name,
                    image, process_name, command, privileged, capabilities, host_mounts,
                    env_vars, network_activity, file_operations, syscall_frequency,
                    classification, risk_score, confidence,
                    full_falco_event, extracted_features_json, behavioral_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp, event.admission_controller_name, event.namespace,
                event.pod_name, event.container_name, event.image, event.process_name,
                event.command, event.privileged, json.dumps(event.capabilities),
                json.dumps(event.host_mounts), json.dumps(event.env_vars),
                event.network_activity, event.file_operations, event.syscall_frequency,
                event.classification, event.risk_score, event.confidence,
                json.dumps(falco_event) if falco_event else None,
                json.dumps(features_dict),
                behavioral_sig
            ))
            
            # Also store in legacy table for backward compatibility
            cursor.execute("""
                INSERT INTO admission_controller_events (
                    timestamp, admission_controller_name, namespace, pod_name, container_name,
                    image, process_name, command, privileged, capabilities, host_mounts,
                    env_vars, network_activity, file_operations, syscall_frequency,
                    classification, risk_score, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp, event.admission_controller_name, event.namespace,
                event.pod_name, event.container_name, event.image, event.process_name,
                event.command, event.privileged, json.dumps(event.capabilities),
                json.dumps(event.host_mounts), json.dumps(event.env_vars),
                event.network_activity, event.file_operations, event.syscall_frequency,
                event.classification, event.risk_score, event.confidence
            ))
        
        conn.commit()
        conn.close()
        
        # Update behavioral profiles after main transaction completes
        for i, event in enumerate(events):
            falco_event = falco_events[i] if falco_events and i < len(falco_events) else None
            features_df = self._extract_ml_features([event])
            features_dict = features_df.iloc[0].to_dict() if not features_df.empty else {}
            if features_dict:
                self._update_behavioral_profile(event.admission_controller_name, features_dict, event.risk_score)
        
        logger.info(f"Stored {len(events)} events in database with behavioral context")
    
    def _store_events(self, events: List[AdmissionControllerEvent]):
        """Legacy storage method for backward compatibility"""
        # Call new method with no Falco events
        self._store_events_with_context(events, None)
    
    def _extract_forensic_details(self, controller_events: List[AdmissionControllerEvent]) -> Dict[str, Any]:
        """Extract forensic details to answer the 9 critical questions"""
        if not controller_events:
            return {}
        
        # Get earliest and latest events for timeline
        timestamps = [e.timestamp for e in controller_events if e.timestamp]
        earliest_event = min(controller_events, key=lambda x: x.timestamp) if timestamps else controller_events[0]
        latest_event = max(controller_events, key=lambda x: x.timestamp) if timestamps else controller_events[0]
        
        # Extract unique values across all events
        namespaces = set([e.namespace for e in controller_events if e.namespace])
        pods = set([e.pod_name for e in controller_events if e.pod_name])
        containers = set([e.container_name for e in controller_events if e.container_name])
        images = set([e.image for e in controller_events if e.image])
        processes = set([e.process_name for e in controller_events if e.process_name])
        commands = set([e.command for e in controller_events if e.command])
        
        # Analyze success/failure patterns
        successful_ops = sum(1 for e in controller_events if 'mount' in e.process_name.lower())
        failed_ops = sum(1 for e in controller_events if 'error' in e.command.lower() or 'fail' in e.command.lower())
        
        # Attack patterns
        attack_indicators = []
        for event in controller_events:
            if event.privileged:
                attack_indicators.append("Privileged execution")
            if len(event.capabilities) > 3:
                attack_indicators.append("Excessive capabilities")
            if event.host_mounts:
                attack_indicators.append("Host filesystem access")
            if any(sus in event.command.lower() for sus in ['curl', 'wget', 'nc', 'bash']):
                attack_indicators.append("Suspicious command execution")
        
        return {
            'earliest_time': earliest_event.timestamp if timestamps else 'Unknown',
            'latest_time': latest_event.timestamp if timestamps else 'Unknown',
            'duration': f"{len(timestamps)} events over time period" if len(timestamps) > 1 else "Single event",
            'namespaces': list(namespaces),
            'pods': list(pods),
            'containers': list(containers),
            'images': list(images),
            'processes': list(processes),
            'commands': list(commands),
            'successful_operations': successful_ops,
            'failed_operations': failed_ops,
            'attack_indicators': list(set(attack_indicators)),
            'repeat_activity': len(controller_events) > 1,
            'affected_resources': {
                'namespaces': len(namespaces),
                'pods': len(pods),
                'containers': len(containers)
            }
        }
    
    
    def _generate_controller_report(self, events: List[AdmissionControllerEvent], is_baseline: bool = False):
        """Generate admission controller report grouped by controller name"""
        # Group events by admission controller name
        controller_groups = {}
        for event in events:
            controller_name = event.admission_controller_name
            if controller_name not in controller_groups:
                controller_groups[controller_name] = []
            controller_groups[controller_name].append(event)
        
        # Generate report with standard naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_type = "baseline" if is_baseline else "activity"
        report_file = self.test_results_dir / f"{report_type}_report_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("ADMISSION CONTROLLER ML ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Events: {len(events)}\n")
            f.write(f"Controllers Analyzed: {len(controller_groups)}\n\n")
            
            for controller_name, controller_events in controller_groups.items():
                f.write(f"ADMISSION CONTROLLER: {controller_name}\n")
                f.write("-" * 40 + "\n")
                
                # Calculate statistics
                classifications = [e.classification for e in controller_events if e.classification]
                risk_scores = [e.risk_score for e in controller_events if e.risk_score is not None]
                
                classification_counts = {}
                for cls in classifications:
                    classification_counts[cls] = classification_counts.get(cls, 0) + 1
                
                f.write(f"  Event Count: {len(controller_events)}\n")
                f.write(f"  Classifications:\n")
                for cls, count in classification_counts.items():
                    f.write(f"    {cls}: {count} events\n")
                
                if risk_scores:
                    f.write(f"  Risk Score: {max(risk_scores):.3f} (max), {np.mean(risk_scores):.3f} (avg)\n")
                
                # Show ML classification factors for this controller
                self._write_controller_ml_factors(f, controller_events)
                
                f.write("\n")
        
        logger.info(f"Report generated: {report_file}")
    
    def _write_controller_ml_factors(self, f, controller_events: List[AdmissionControllerEvent]):
        """Write ML classification factors that influenced the controller's risk assessment"""
        if not controller_events:
            return
            
        # Extract features for this controller's events
        features_df = self._extract_ml_features(controller_events)
        if features_df.empty:
            return
            
        # Get feature importance from trained classifier if available
        feature_importance = {}
        if hasattr(self.random_forest, 'feature_importances_') and len(self.feature_names) > 0:
            for name, importance in zip(self.feature_names, self.random_forest.feature_importances_):
                if importance > 0.001:  # Only show meaningful features
                    feature_importance[name] = importance
        
        # Analyze which features are active for this controller
        active_features = {}
        for col in features_df.columns:
            values = features_df[col].values
            if any(v > 0 for v in values):  # Feature is active
                max_val = max(values)
                avg_val = sum(values) / len(values)
                active_features[col] = {'max': max_val, 'avg': avg_val}
        
        if active_features or feature_importance:
            f.write("  ML Classification Factors:\n")
            
            # Show important active features
            important_active = {}
            for feature in active_features:
                if feature in feature_importance:
                    important_active[feature] = {
                        'importance': feature_importance[feature],
                        'values': active_features[feature]
                    }
            
            if important_active:
                f.write("    Key Contributing Features:\n")
                # Sort by importance
                sorted_features = sorted(important_active.items(), key=lambda x: x[1]['importance'], reverse=True)
                for feature, data in sorted_features[:8]:  # Show top 8 features
                    importance = data['importance']
                    avg_val = data['values']['avg']
                    f.write(f"      - {feature}: {avg_val:.3f} (importance: {importance:.3f})\n")
            elif active_features:
                f.write("    Active Security Features:\n")
                # Show active features sorted by average value when no importance available
                sorted_features = sorted(active_features.items(), key=lambda x: x[1]['avg'], reverse=True)
                for feature, values in sorted_features[:8]:  # Show top 8 active features
                    avg_val = values['avg']
                    max_val = values['max']
                    
                    # Use consistent avg/max format for all features
                    f.write(f"      - {feature}: avg={avg_val:.3f}, max={max_val:.3f}\n")
            
            # Show risk indicators based on feature categories
            risk_categories = self._categorize_risk_features(active_features)
            if risk_categories:
                f.write("    Risk Category Summary:\n")
                for category, features in risk_categories.items():
                    if features:
                        f.write(f"      - {category}: {len(features)} indicators\n")
    
    def _categorize_risk_features(self, active_features: dict) -> dict:
        """Categorize active features into risk categories for easier interpretation"""
        categories = {
            'Process Risks': [],
            'File Access Risks': [],  
            'Network Risks': [],
            'Container Risks': [],
            'Security Violations': [],
            'Kubernetes Risks': []
        }
        
        for feature in active_features:
            if any(x in feature.lower() for x in ['process', 'command', 'privileged', 'capability']):
                categories['Process Risks'].append(feature)
            elif 'file' in feature.lower() or 'config' in feature.lower():
                categories['File Access Risks'].append(feature)
            elif 'network' in feature.lower() or 'connection' in feature.lower():
                categories['Network Risks'].append(feature) 
            elif 'container' in feature.lower() or 'mount' in feature.lower():
                categories['Container Risks'].append(feature)
            elif 'violation' in feature.lower() or 'escalation' in feature.lower():
                categories['Security Violations'].append(feature)
            elif any(x in feature.lower() for x in ['namespace', 'rbac', 'api', 'kubernetes']):
                categories['Kubernetes Risks'].append(feature)
        
        return categories
    
    def _is_binary_feature(self, feature_name: str) -> bool:
        """Check if a feature is binary (0/1) vs continuous"""
        binary_features = {
            'suspicious_binary_execution', 'webhook_mutating', 'webhook_validating',
            'webhook_port_standard', 'webhook_tls_cert', 'webhook_config_mount',
            'admission_review_processing', 'webhook_server_running', 'kubernetes_api_calls',
            'process_privileged', 'process_capabilities', 'process_shell_access',
            'process_suspicious_commands', 'file_sensitive_access', 'file_config_write',
            'file_certificate_access', 'file_host_filesystem_access', 'file_log_manipulation',
            'file_secrets_access', 'network_activity_detected', 'network_outbound_connections', 'outbound_connections',
            'network_suspicious_domains', 'network_port_scanning', 'network_dns_queries',
            'container_privileged_execution', 'container_volume_host_access',
            'container_environment_modification', 'container_runtime_access',
            'namespace_cross_access', 'pod_security_context_manipulation',
            'service_account_manipulation', 'rbac_privilege_escalation',
            'api_server_direct_communication', 'privilege_escalation_detected',
            'anomalous_process_behavior', 'persistence_mechanism_detected',
            'data_exfiltration_signs'
        }
        return feature_name in binary_features
    
    def _generate_empty_activity_report(self, events: List[AdmissionControllerEvent], baseline_controllers: set):
        """Generate activity report when only baseline controllers are detected"""
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.test_results_dir / f"activity_report_{timestamp}.txt"
        
        # Count detected controllers
        detected_controllers = {}
        for event in events:
            if event.admission_controller_name:
                detected_controllers[event.admission_controller_name] = detected_controllers.get(event.admission_controller_name, 0) + 1
        
        with open(report_path, 'w') as f:
            f.write("FALCO ML ACTIVITY TRAINING REPORT\n")
            f.write("=================================\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-----------------\n")
            f.write(f"Training Data: {len(events)} Falco events analyzed\n")
            f.write(f"New Controllers: 0 (all detected controllers are baseline)\n")
            f.write("Result: No new admission controllers detected for threat analysis\n")
            f.write("Purpose: Identify malicious or suspicious admission controllers\n\n")
            
            f.write("ANALYSIS RESULTS\n")
            f.write("----------------\n")
            f.write("No new admission controllers found after filtering baseline controllers.\n")
            f.write("All detected admission controller activity belongs to known baseline controllers.\n\n")
            
            if detected_controllers:
                f.write("DETECTED CONTROLLERS\n")
                f.write("-------------------\n")
                for controller, count in detected_controllers.items():
                    f.write(f"- {controller}: {count} events\n")
                f.write("\n")
            
            f.write("RECOMMENDATION\n")
            f.write("--------------\n")
            f.write("Deploy additional malicious or suspicious admission controllers to generate\n")
            f.write("training data that differs from the baseline behavioral patterns.\n\n")
            
            f.write(f"--- Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        
        logger.info(f"Empty activity report generated: {report_path}")
    
    def _generate_structured_training_report(self, events: List[AdmissionControllerEvent], y_true: List[str], 
                                           train_accuracy: float, train_report: str, is_baseline: bool):
        """Generate clean, focused ML training report for this Falco security project"""
        
        # Determine report filename and type
        if is_baseline:
            report_path = self.test_results_dir / "baseline_training_report.txt"
            report_title = "FALCO ML BASELINE TRAINING REPORT"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = self.test_results_dir / f"activity_report_{timestamp}.txt"
            report_title = "FALCO ML THREAT DETECTION TRAINING REPORT"
        
        # Get key statistics
        controller_names = [e.admission_controller_name for e in events]
        unique_controllers = set(controller_names)
        
        # Calculate risk statistics  
        risk_scores = [e.risk_score for e in events if e.risk_score is not None]
        max_risk = max(risk_scores) if risk_scores else 0
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Get meaningful feature importance
        meaningful_features = []
        if hasattr(self.random_forest, 'feature_importances_') and len(self.feature_names) > 0:
            feature_importance = list(zip(self.feature_names, self.random_forest.feature_importances_))
            meaningful_features = [(name, imp) for name, imp in feature_importance if imp > 0.001]
            meaningful_features.sort(key=lambda x: x[1], reverse=True)
        
        with open(report_path, "w") as f:
            f.write(f"{report_title}\n")
            f.write("=" * len(report_title) + "\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 17 + "\n")
            f.write(f"Training Data: {len(events)} Falco events from {len(unique_controllers)} admission controllers\n")
            f.write(f"Controllers: {', '.join(sorted(unique_controllers))}\n")
            if is_baseline:
                f.write("Purpose: Establish baseline behavioral patterns for legitimate webhooks\n")
                f.write("ML Approach: Unsupervised anomaly detection (Isolation Forest)\n")
                f.write("  - Model: Isolation Forest with contamination detection\n")
                f.write("  - Purpose: Establish normal behavior boundaries\n")
                f.write("  - Method: Tree-based isolation for outlier detection\n")
            else:
                f.write("Purpose: Analyze admission controller events against baseline to detect deviations\n")
                f.write("ML Approach: Supervised classification + anomaly detection\n")
                f.write("  - Primary Model: Random Forest Classifier (100 estimators)\n")
                f.write("  - Secondary Model: Isolation Forest (anomaly detection)\n")
                f.write("  - Feature Engineering: 43 behavioral security features\n")
                f.write("  - Baseline Comparison: Detect deviations from normal behavior patterns\n")
                f.write("  - Classification: MALICIOUS/SUSPICIOUS/LEGITIMATE\n")
            
            # Risk score analysis
            f.write(f"Risk Score Range: {max_risk:.3f} (max) | {avg_risk:.3f} (avg)\n")
            if risk_scores:
                min_risk = min(risk_scores)
                risk_std = (sum((x - avg_risk) ** 2 for x in risk_scores) / len(risk_scores)) ** 0.5
                f.write(f"  - Score Distribution: {min_risk:.3f} (min) to {max_risk:.3f} (max)\n")
                f.write(f"  - Standard Deviation: {risk_std:.3f} (variation measure)\n")
                f.write(f"  - Sample Size: {len(risk_scores)} scored events\n")
            f.write("\n")
            
            # Risk Assessment
            triggered_thresholds = self._get_triggered_risk_thresholds(events)
            if triggered_thresholds:
                f.write("\nRisk Thresholds Triggered:\n")
                for threshold_name, threshold_value in triggered_thresholds.items():
                    if threshold_name == 'MALICIOUS':
                        f.write(f"  CRITICAL {threshold_name}: >= {threshold_value} (Critical threats detected)\n")
                    elif threshold_name == 'SUSPICIOUS':  
                        f.write(f"  ALERT {threshold_name}: >= {threshold_value} (Medium risk activities)\n")
                    elif threshold_name == 'LEGITIMATE':
                        f.write(f"  NORMAL {threshold_name}: < {self._get_risk_thresholds()['SUSPICIOUS']} (Normal behavior)\n")
            
            f.write("\n")
            
            # Security Insights
            f.write("SECURITY INSIGHTS\n")
            f.write("-" * 17 + "\n")
            
            if is_baseline:
                # Analyze baseline patterns
                privileged_events = sum(1 for e in events if e.privileged)
                network_events = sum(1 for e in events if e.network_activity)
                unique_commands = len(set(e.command for e in events))
                unique_namespaces = len(set(e.namespace for e in events))
                
                f.write("Baseline Behavioral Profile:\n")
                
                # Only show behaviors that were actually detected
                if network_events > 0:
                    f.write(f"  - Network Activity: {network_events}/{len(events)} events\n")
                
                if privileged_events > 0:
                    f.write(f"  - Privileged Operations: {privileged_events}/{len(events)} events\n")
                
                f.write(f"  - Command Diversity: {unique_commands} unique commands\n")
                f.write(f"  - Namespace Distribution: {unique_namespaces} namespaces\n")
                
                f.write("\nBaseline Security Assessment:\n")
                if max_risk > 0.5:
                    f.write("  WARNING: Elevated Risk: Some baseline controllers show suspicious patterns\n")
                    f.write("     Recommendation: Review high-risk events for false positives\n")
                else:
                    f.write("  NORMAL: Normal Risk: Baseline controllers show expected behavior\n")
                    f.write("     Status: Ready for threat detection training\n")
            else:
                # Analyze threat patterns
                malicious_events = sum(1 for e in events if e.classification == 'MALICIOUS')
                suspicious_events = sum(1 for e in events if e.classification == 'SUSPICIOUS')
                
                f.write("Threat Detection Profile:\n")
                
                # Show detected threat levels
                if malicious_events > 0:
                    f.write(f"  - Malicious Events Detected: {malicious_events} events\n")
                if suspicious_events > 0:
                    f.write(f"  - Suspicious Events Detected: {suspicious_events} events\n")
                
                # Show total for context
                f.write(f"  - Total Events Analyzed: {len(events)}\n")
                
                if meaningful_features:
                    f.write(f"  - Attack Indicators: {len(meaningful_features)} ML features learned\n")
                    f.write("  - Detection Capability: Supervised classification enabled\n")
                else:
                    f.write("  - Attack Indicators: Insufficient variation for feature learning\n")
                    f.write("  - Detection Capability: Anomaly detection only\n")
            
            f.write("\n")
            
            # Detailed Controller Analysis with ML Factors
            f.write("DETAILED CONTROLLER ANALYSIS\n")
            f.write("-" * 30 + "\n")
            
            # Group events by controller for detailed analysis
            controller_groups = {}
            for event in events:
                controller_name = event.admission_controller_name
                if controller_name not in controller_groups:
                    controller_groups[controller_name] = []
                controller_groups[controller_name].append(event)
            
            for controller_name, controller_events in sorted(controller_groups.items()):
                f.write(f"\nController: {controller_name}\n")
                f.write("-" * (len(controller_name) + 12) + "\n")
                
                # Basic statistics
                classifications = [e.classification for e in controller_events if e.classification]
                risk_scores = [e.risk_score for e in controller_events if e.risk_score is not None]
                
                classification_counts = {}
                for cls in classifications:
                    classification_counts[cls] = classification_counts.get(cls, 0) + 1
                
                f.write(f"Events: {len(controller_events)}\n")
                if classification_counts:
                    f.write("Classifications: ")
                    for cls, count in sorted(classification_counts.items()):
                        f.write(f"{cls}({count}) ")
                    f.write("\n")
                
                if risk_scores:
                    max_risk = max(risk_scores)
                    avg_risk = sum(risk_scores) / len(risk_scores)
                    f.write(f"Risk Score: {max_risk:.3f} (max) | {avg_risk:.3f} (avg)\n")
                
                # Add classification factors based on trained classifier's feature importance
                try:
                    # Use the trained classifier's feature importance if available
                    if hasattr(self.random_forest, 'feature_importances_') and len(self.feature_names) > 0:
                        # Get feature importance from trained classifier
                        feature_importance = list(zip(self.feature_names, self.random_forest.feature_importances_))
                        important_features = [(name, imp) for name, imp in feature_importance if imp > 0.001]
                        important_features.sort(key=lambda x: x[1], reverse=True)
                        
                        if important_features:
                            f.write("Classification Factors (Feature Importance):\n")
                            # Show top features that the classifier learned as important
                            for feature, importance in important_features[:5]:  # Show top 5
                                f.write(f"  - {feature}: importance={importance:.4f}\n")
                        else:
                            # Even if classifier has no discriminative features, show active features for this controller
                            features_df = self._extract_ml_features(controller_events)
                            if not features_df.empty:
                                active_features = {}
                                for col in features_df.columns:
                                    values = features_df[col].values
                                    if any(v > 0 for v in values):
                                        max_val = max(values)
                                        avg_val = sum(values) / len(values)
                                        active_features[col] = {'max': max_val, 'avg': avg_val}
                                
                                if active_features:
                                    f.write("ML Classification Factors (Active Features):\n")
                                    sorted_features = sorted(active_features.items(), key=lambda x: x[1]['avg'], reverse=True)
                                    for feature, values in sorted_features[:5]:  # Show top 5
                                        avg_val = values['avg']
                                        max_val = values['max']
                                        
                                        # Use consistent avg/max format for all features
                                        f.write(f"  - {feature}: avg={avg_val:.3f}, max={max_val:.3f}\n")
                                else:
                                    f.write("ML Classification Factors: No discriminative features learned\n")
                            else:
                                f.write("ML Classification Factors: No discriminative features learned\n")
                    else:
                        # Extract features for controller events
                        features_df = self._extract_ml_features(controller_events)
                        if not features_df.empty:
                            # Analyze active features
                            active_features = {}
                            for col in features_df.columns:
                                values = features_df[col].values
                                if any(v > 0 for v in values):
                                    max_val = max(values)
                                    avg_val = sum(values) / len(values)
                                    active_features[col] = {'max': max_val, 'avg': avg_val}
                            
                            if active_features:
                                f.write("ML Classification Factors (Active Features):\n")
                                sorted_features = sorted(active_features.items(), key=lambda x: x[1]['avg'], reverse=True)
                                for feature, values in sorted_features[:5]:  # Show top 5
                                    avg_val = values['avg']
                                    max_val = values['max']
                                    
                                    # Use consistent avg/max format for all features
                                    f.write(f"  - {feature}: avg={avg_val:.3f}, max={max_val:.3f}\n")
                            else:
                                f.write("ML Classification Factors: No active features detected\n")
                        else:
                            f.write("ML Classification Factors: Unable to extract features\n")
                except Exception as e:
                    f.write(f"ML Analysis: Error analyzing features ({str(e)})\n")
            
            f.write("\n")
            
            # Next Steps
            f.write("NEXT STEPS\n")
            f.write("-" * 10 + "\n")
            if is_baseline:
                f.write("1. Deploy malicious admission controllers for threat pattern collection\n")
                f.write("2. Train threat detection classifiers on attack data\n")
                f.write("3. Validate detection accuracy and tune thresholds\n")
            else:
                if meaningful_features:
                    f.write("1. Validate classifier performance on unseen data\n")
                    f.write("2. Deploy for real-time threat detection\n")
                    f.write("3. Monitor and tune based on false positive rates\n")
                else:
                    f.write("1. Collect more diverse attack data for better feature learning\n")
                    f.write("2. Enhance feature engineering for better discrimination\n")
                    f.write("3. Consider ensemble methods for improved detection\n")
            
            f.write(f"\n--- Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        
        logger.info(f"Clean ML training report generated: {report_path}")
    def _categorize_features(self) -> Dict[str, List[str]]:
        """Dynamically categorize features based on actual feature names"""
        categories = {
            "Core Admission Controller": [],
            "Process Indicators": [],
            "File Access Indicators": [],
            "Network Behavior": [],
            "Container Indicators": [],
            "Kubernetes Context": [],
            "Security Violations": [],
            "Threat Indicators": []
        }
        
        for feature_name in self.feature_names:
            if any(keyword in feature_name for keyword in ['webhook', 'admission', 'mutating', 'validating', 'kubernetes_api']):
                categories["Core Admission Controller"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['process', 'command', 'capabilities', 'shell']):
                categories["Process Indicators"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['file', 'config', 'certificate', 'host_filesystem', 'log', 'secrets']):
                categories["File Access Indicators"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['network', 'outbound', 'domains', 'port_scanning', 'dns']):
                categories["Network Behavior"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['container', 'privileged', 'volume', 'environment', 'runtime']):
                categories["Container Indicators"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['namespace', 'pod_security', 'service_account', 'rbac', 'api_server']):
                categories["Kubernetes Context"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['privilege_escalation', 'suspicious_binary', 'anomalous']):
                categories["Security Violations"].append(feature_name)
            elif any(keyword in feature_name for keyword in ['persistence', 'exfiltration', 'obfuscation']):
                categories["Threat Indicators"].append(feature_name)
            else:
                # Fallback category for uncategorized features
                if "Uncategorized" not in categories:
                    categories["Uncategorized"] = []
                categories["Uncategorized"].append(feature_name)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _categorize_features_with_importance(self) -> Dict[str, List[str]]:
        """Categorize features based on actual feature names and filter by importance"""
        if not hasattr(self.random_forest, 'feature_importances_') or len(self.feature_names) == 0:
            return {}
        
        # Get features with meaningful importance
        feature_importance = dict(zip(self.feature_names, self.random_forest.feature_importances_))
        meaningful_features = {name for name, imp in feature_importance.items() if imp > 0.0001}
        
        if not meaningful_features:
            return {}
        
        # Get all categories
        all_categories = self._categorize_features()
        
        # Filter categories to only include those with meaningful features
        filtered_categories = {}
        for category, features in all_categories.items():
            meaningful_in_category = [f for f in features if f in meaningful_features]
            if meaningful_in_category:
                filtered_categories[category] = meaningful_in_category
        
        return filtered_categories
    
    def _get_meaningful_classifier_parameters(self) -> Dict[str, Dict[str, any]]:
        """Get only non-default and meaningful classifier parameters"""
        meaningful_params = {}
        
        if hasattr(self, 'random_forest') and self.random_forest is not None:
            rf_params = {}
            # Only include non-default parameters
            if self.random_forest.n_estimators != 100:
                rf_params['n_estimators'] = self.random_forest.n_estimators
            if self.random_forest.random_state is not None:
                rf_params['random_state'] = self.random_forest.random_state
            if self.random_forest.max_depth is not None:  # Default is None, but always show if set
                rf_params['max_depth'] = self.random_forest.max_depth
            # Skip min_samples_split and min_samples_leaf as they are defaults (2 and 1)
            
            if rf_params:
                meaningful_params['random_forest'] = rf_params
        
        if hasattr(self, 'isolation_forest') and self.isolation_forest is not None:
            if_params = {}
            # Only include non-default parameters
            if self.isolation_forest.contamination != 0.1:
                if_params['contamination'] = self.isolation_forest.contamination
            if self.isolation_forest.random_state is not None:
                if_params['random_state'] = self.isolation_forest.random_state
            if self.isolation_forest.n_estimators != 100:
                if_params['n_estimators'] = self.isolation_forest.n_estimators
            # Skip max_samples as 'auto' is default
            
            if if_params:
                meaningful_params['isolation_forest'] = if_params
        
        return meaningful_params
    
    def _get_risk_thresholds(self) -> Dict[str, float]:
        """Extract actual risk thresholds from _classify_risk method"""
        # These should match the actual thresholds in _classify_risk
        return {
            'MALICIOUS': self.RISK_THRESHOLD_MALICIOUS,
            'SUSPICIOUS': self.RISK_THRESHOLD_SUSPICIOUS,
            'LEGITIMATE': 0.0
        }
    
    def _get_triggered_risk_thresholds(self, events: List[AdmissionControllerEvent]) -> Dict[str, float]:
        """Get only risk thresholds that were actually triggered by events"""
        thresholds = self._get_risk_thresholds()
        triggered = {}
        
        # Get all risk scores from events
        risk_scores = [event.risk_score for event in events if event.risk_score is not None]
        
        if not risk_scores:
            return {}
        
        max_risk = max(risk_scores)
        min_risk = min(risk_scores)
        
        # Only include thresholds that were actually crossed
        if max_risk >= thresholds['MALICIOUS']:
            triggered['MALICIOUS'] = thresholds['MALICIOUS']
        
        if max_risk >= thresholds['SUSPICIOUS']:
            triggered['SUSPICIOUS'] = thresholds['SUSPICIOUS']
        
        # Always include LEGITIMATE if there are any events below SUSPICIOUS threshold
        if min_risk < thresholds['SUSPICIOUS']:
            triggered['LEGITIMATE'] = thresholds['LEGITIMATE']
        
        return triggered
    
    
    def _deploy_malicious_controller(self):
        """Deploy sophisticated malicious admission controller"""
        logger.info("Deploying sophisticated malicious admission controller")
        
        import subprocess
        import os
        
        # Use the fixed malicious deployment that actually works
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        deployment_file = os.path.join(project_dir, 'setup', 'fixed_malicious_deployment.yaml')
        webhook_script = os.path.join(project_dir, 'config', 'sophisticated_malicious_webhook.py')
        
        if not os.path.exists(deployment_file):
            logger.error(f"Malicious deployment file not found: {deployment_file}")
            return
        
        if not os.path.exists(webhook_script):
            logger.error(f"Malicious webhook script not found: {webhook_script}")
            return
        
        try:
            # Create monitoring-system namespace
            logger.info("Creating monitoring-system namespace...")
            subprocess.run([
                'kubectl', 'create', 'namespace', 'monitoring-system'
            ], capture_output=True, text=True, check=False)  # Ignore if exists
            
            # Create ConfigMap with the sophisticated webhook script
            logger.info("Creating malicious webhook script ConfigMap...")
            with open(webhook_script, 'r') as f:
                script_content = f.read()
            
            subprocess.run([
                'kubectl', 'create', 'configmap', 'malicious-webhook-script',
                '--from-literal=webhook.py=' + script_content,
                '-n', 'monitoring-system'
            ], capture_output=True, text=True, check=False)  # Ignore if exists
            
            # Generate webhook certificates
            logger.info("Generating webhook certificates...")
            
            # Generate certificates for monitoring-agent if they don't exist
            certs_dir = os.path.join(project_dir, 'certs')
            monitoring_agent_cert = os.path.join(certs_dir, 'monitoring-agent.crt')
            monitoring_agent_key = os.path.join(certs_dir, 'monitoring-agent.key')
            
            if not os.path.exists(monitoring_agent_cert) or not os.path.exists(monitoring_agent_key):
                # Use the certificate generation script
                cert_script = os.path.join(project_dir, 'setup', 'generate_certs.sh')
                if os.path.exists(cert_script):
                    subprocess.run([cert_script, 'monitoring-agent'], 
                                 capture_output=True, text=True, check=False)
            
            # Create the secret with the generated certificates
            if os.path.exists(monitoring_agent_cert) and os.path.exists(monitoring_agent_key):
                subprocess.run([
                    'kubectl', 'create', 'secret', 'tls', 'monitoring-agent-certs',
                    f'--cert={monitoring_agent_cert}',
                    f'--key={monitoring_agent_key}',
                    '-n', 'monitoring-system'
                ], capture_output=True, text=True, check=False)
            else:
                logger.warning("Certificate files not found, creating dummy certificates")
                # Create a simple self-signed certificate as fallback
                subprocess.run([
                    'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', 
                    '/tmp/monitoring-agent.key', '-out', '/tmp/monitoring-agent.crt',
                    '-days', '30', '-nodes', '-subj', 
                    '/CN=monitoring-agent.monitoring-system.svc'
                ], capture_output=True, text=True, check=False)
                
                subprocess.run([
                    'kubectl', 'create', 'secret', 'tls', 'monitoring-agent-certs',
                    '--cert=/tmp/monitoring-agent.crt',
                    '--key=/tmp/monitoring-agent.key',
                    '-n', 'monitoring-system'
                ], capture_output=True, text=True, check=False)
            
            # Deploy the malicious controller
            logger.info("Deploying monitoring-agent malicious controller...")
            result = subprocess.run([
                'kubectl', 'apply', '-f', deployment_file
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to deploy malicious controller: {result.stderr}")
                return
            
            # Create webhook configuration
            logger.info("Creating malicious webhook configuration...")
            webhook_config = '''
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionWebhookConfiguration
metadata:
  name: monitoring-agent-webhook
webhooks:
- name: monitoring-agent-webhook.monitoring-system.svc
  clientConfig:
    service:
      name: monitoring-agent-service
      namespace: monitoring-system
      path: "/mutate"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  namespaceSelector: {}
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
'''
            
            subprocess.run([
                'kubectl', 'apply', '-f', '-'
            ], input=webhook_config, text=True, capture_output=True)
            
            logger.info("Sophisticated malicious admission controller deployed successfully")
            logger.info("Controller name: monitoring-agent")
            logger.info("Namespace: monitoring-system")
            logger.info("Features: Multi-stage attack simulation, privilege escalation, data exfiltration")
            
        except Exception as e:
            logger.error(f"Failed to deploy malicious controller: {e}")

    def _generate_malicious_workloads(self, duration: int):
        """Generate webhook-triggering workloads to create admission controller events"""
        logger.info(f"Generating malicious workloads for {duration} seconds")
        
        import subprocess
        import time
        
        try:
            # Create webhook-triggering pods that will go through the malicious webhook
            for i in range(min(5, duration // 60)):  # Create up to 5 pods, 1 per minute
                pod_name = f"log-processor-{i+1}"
                logger.info(f"Creating workload pod: {pod_name}")
                
                pod_yaml = f'''
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: monitoring-system
  labels:
    app: log-processor
    component: data-analytics
  annotations:
    log.processor/enabled: "true"
    monitoring.system/collect: "true"
spec:
  containers:
  - name: log-collector
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "
      echo 'Starting log processing service...';
      
      # Process service tokens
      cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 50 || true;
      
      # Connect to API for metrics
      wget -qO- http://kubernetes.default/api/v1 || true;
      
      # Check system capabilities
      cat /proc/self/status | grep Cap || true;
      
      sleep 120;
      echo 'Log processing completed';
    "]
    securityContext:
      privileged: true
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN"]
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
  restartPolicy: Never
'''
                
                # Apply the pod (this will trigger the malicious webhook)
                result = subprocess.run([
                    'kubectl', 'apply', '-f', '-'
                ], input=pod_yaml, text=True, capture_output=True)
                
                if result.returncode == 0:
                    logger.info(f"Successfully created {pod_name} - processing workload deployed")
                    time.sleep(60)  # Wait 1 minute between pods
                else:
                    logger.warning(f"Failed to create {pod_name}: {result.stderr}")
                    
        except Exception as e:
            logger.error(f"Failed to generate malicious workloads: {e}")
        
        logger.info("Workload generation completed")

def main():
    """Main entry point for command line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Admission Controller Detection Pipeline')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Train from JSON command
    train_parser = subparsers.add_parser('train-from-json', help='Train classifiers from Falco JSON log file')
    train_parser.add_argument('--input', required=True, help='Path to Falco JSON log file')
    
    # Controller report command
    report_parser = subparsers.add_parser('controller-report', help='Generate admission controller threat report')
    report_parser.add_argument('--input', help='Path to specific Falco JSON log file')
    report_parser.add_argument('--output', help='Output report file path')
    
    # Feedback review command
    feedback_parser = subparsers.add_parser('feedback-review', help='Interactive feedback review system')
    
    # Batch feedback command
    batch_feedback_parser = subparsers.add_parser('batch-feedback', help='Apply feedback to specific controller')
    batch_feedback_parser.add_argument('--controller', required=True, help='Admission controller name')
    batch_feedback_parser.add_argument('--classification', required=True, choices=['LEGITIMATE', 'SUSPICIOUS', 'MALICIOUS'], help='Corrected classification')
    batch_feedback_parser.add_argument('--comment', default='', help='Optional comment for the feedback')
    
    # Deploy baseline command (internal use)
    baseline_parser = subparsers.add_parser('deploy-baseline', help='Deploy baseline admission controllers')
    baseline_parser.add_argument('--duration', type=int, default=600, help='Deployment duration in seconds')
    
    # Deploy malicious command (internal use) 
    malicious_parser = subparsers.add_parser('deploy-malicious', help='Deploy malicious admission controller')
    malicious_parser.add_argument('--duration', type=int, default=600, help='Deployment duration in seconds')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Create pipeline instance
    pipeline = AdmissionControllerDetectionPipeline()
    
    if args.command == 'train-from-json':
        pipeline.train_from_json(args.input)
    elif args.command == 'controller-report':
        pipeline.controller_report(args.input, args.output)
    elif args.command == 'feedback-review':
        pipeline.feedback_review()
    elif args.command == 'batch-feedback':
        pipeline.batch_feedback(args.controller, args.classification, args.comment)
    elif args.command == 'deploy-baseline':
        pipeline.deploy_baseline(args.duration)
    elif args.command == 'deploy-malicious':
        pipeline.deploy_malicious(args.duration)
    
if __name__ == "__main__":
    main()
