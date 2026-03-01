"""
============================================================
lambda-functions/lambda_log_receiver.py
Cloud-Based Log Monitoring & Alerting System
============================================================
This Lambda function:
  1. Receives log entry from API Gateway (from website)
  2. Saves log to S3 as JSON
  3. Analyses logs and pushes metrics to CloudWatch
  4. Returns response to browser

Trigger: API Gateway POST request
============================================================
"""

import boto3
import json
import datetime
import os
import uuid
from collections import Counter

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
BUCKET_NAME = os.environ.get("BUCKET_NAME", "log-monitor-internship-2024")
NAMESPACE   = os.environ.get("NAMESPACE",   "LogMonitor/WebLogs")
REGION      = os.environ.get("REGION",      "us-east-1")

# Anomaly threshold
SUSPICIOUS_THRESHOLD = 50  # requests per IP per session

# In-memory store for this Lambda instance
# (resets when Lambda cold starts)
ip_request_counts = {}


def handler(event, context):
    """
    Main Lambda entry point.
    Called by API Gateway when website sends a log entry.
    """
    print(f"Event received: {json.dumps(event)}")

    # ── Handle CORS preflight (OPTIONS request from browser) ──
    if event.get("httpMethod") == "OPTIONS":
        return cors_response(200, {"message": "OK"})

    try:
        # ── Parse incoming log entry from browser ─────────────
        body = event.get("body", "{}")
        if isinstance(body, str):
            body = json.loads(body)

        # Build complete log entry
        log_entry = build_log_entry(body, event)
        print(f"Log entry: {json.dumps(log_entry)}")

        # ── Save to S3 ────────────────────────────────────────
        save_to_s3(log_entry)

        # ── Push metrics to CloudWatch ────────────────────────
        push_metrics(log_entry)

        return cors_response(200, {
            "message"  : "Log recorded successfully",
            "log_id"   : log_entry["log_id"],
            "timestamp": log_entry["timestamp"],
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return cors_response(500, {"error": str(e)})


def build_log_entry(body: dict, event: dict) -> dict:
    """Build a complete log entry from browser data + server data."""
    now = datetime.datetime.utcnow()

    # Get IP from API Gateway headers
    ip = (
        event.get("requestContext", {})
             .get("identity", {})
             .get("sourceIp", "unknown")
    )

    # Track IP request counts for anomaly detection
    ip_request_counts[ip] = ip_request_counts.get(ip, 0) + 1

    status_code = int(body.get("status_code", 200))

    return {
        "log_id"      : str(uuid.uuid4()),
        "timestamp"   : now.isoformat() + "Z",
        "date"        : now.strftime("%Y-%m-%d"),
        "hour"        : now.hour,
        "ip"          : ip,
        "method"      : body.get("method", "GET"),
        "url"         : body.get("url", "/"),
        "status_code" : status_code,
        "status_class": f"{status_code // 100}xx",
        "action"      : body.get("action", "unknown"),
        "user_agent"  : body.get("user_agent", "unknown"),
        "request_count_this_ip": ip_request_counts.get(ip, 1),
        "suspicious"  : ip_request_counts.get(ip, 1) > SUSPICIOUS_THRESHOLD,
    }


def save_to_s3(log_entry: dict):
    """Save log entry to S3 as a JSON file."""
    s3  = boto3.client("s3", region_name=REGION)
    now = datetime.datetime.utcnow()

    # Organised by date/hour for easy querying
    key = (
        f"raw-logs/live/"
        f"{now.strftime('%Y-%m-%d')}/"
        f"{now.strftime('%H')}/"
        f"{log_entry['log_id']}.json"
    )

    s3.put_object(
        Bucket      = BUCKET_NAME,
        Key         = key,
        Body        = json.dumps(log_entry, indent=2),
        ContentType = "application/json",
    )
    print(f"Saved to S3: {key}")


def push_metrics(log_entry: dict):
    """Push a single log entry's metrics to CloudWatch."""
    cw        = boto3.client("cloudwatch", region_name=REGION)
    timestamp = datetime.datetime.utcnow()
    status    = log_entry["status_class"]

    metric_data = [
        # Count every request
        {
            "MetricName": "TotalRequests",
            "Timestamp" : timestamp,
            "Value"     : 1.0,
            "Unit"      : "Count",
            "Dimensions": [{"Name": "Environment", "Value": "Live"}]
        },
        # Count errors by type
        {
            "MetricName": "Error4xxCount",
            "Timestamp" : timestamp,
            "Value"     : 1.0 if status == "4xx" else 0.0,
            "Unit"      : "Count",
            "Dimensions": [{"Name": "Environment", "Value": "Live"}]
        },
        {
            "MetricName": "Error5xxCount",
            "Timestamp" : timestamp,
            "Value"     : 1.0 if status == "5xx" else 0.0,
            "Unit"      : "Count",
            "Dimensions": [{"Name": "Environment", "Value": "Live"}]
        },
        # Suspicious IP flag
        {
            "MetricName": "SuspiciousIPs",
            "Timestamp" : timestamp,
            "Value"     : 1.0 if log_entry["suspicious"] else 0.0,
            "Unit"      : "Count",
            "Dimensions": [{"Name": "Environment", "Value": "Live"}]
        },
    ]

    cw.put_metric_data(Namespace=NAMESPACE, MetricData=metric_data)
    print(f"Metrics pushed: status={status}, suspicious={log_entry['suspicious']}")


def cors_response(status_code: int, body: dict) -> dict:
    """Return response with CORS headers so browser can receive it."""
    return {
        "statusCode": status_code,
        "headers"   : {
            "Content-Type"                : "application/json",
            "Access-Control-Allow-Origin" : "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(body),
    }