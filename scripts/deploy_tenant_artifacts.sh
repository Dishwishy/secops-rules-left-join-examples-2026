#!/usr/bin/env bash
# Deployment script for Data Table reproduction suites
# Target Tenant: https://<TENANT_DOMAIN>.backstory.chronicle.security/
# Project: <YOUR_GCP_PROJECT_ID>, Location: <LOCATION>, Instance: <YOUR_TENANT_GUID>

set -euo pipefail

echo "==> Fetching gcloud OAuth token..."
TOKEN=$(gcloud auth application-default print-access-token)

PROJECT_ID="<YOUR GCP PROJECT ID>"
LOCATION="us"
INSTANCE_ID="<YOUR TENANT GUID>"
PARENT="projects/${PROJECT_ID}/locations/${LOCATION}/instances/${INSTANCE_ID}"
BASE_URL="https://us-chronicle.googleapis.com/v1alpha/${PARENT}"

echo "==> 1. Creating corporate_asset_directory..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Corporate asset directory for left outer join country and tier enrichment",
    "columnInfo": [
      {"columnIndex": 0, "originalColumn": "hostname", "keyColumn": true, "columnType": "STRING"},
      {"columnIndex": 1, "originalColumn": "country_code", "keyColumn": false, "columnType": "STRING"},
      {"columnIndex": 2, "originalColumn": "country_name", "keyColumn": false, "columnType": "STRING"},
      {"columnIndex": 3, "originalColumn": "asset_tier", "keyColumn": false, "columnType": "STRING"},
      {"columnIndex": 4, "originalColumn": "owner_dept", "keyColumn": false, "columnType": "STRING"},
      {"columnIndex": 5, "originalColumn": "risk_score", "keyColumn": false, "columnType": "NUMBER"}
    ]
  }' \
  "${BASE_URL}/dataTables?dataTableId=corporate_asset_directory" || echo "Table may already exist."

echo "==> 2. Creating authorized_scanners_exclusion..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Authorized scanner hosts for anti-join alert suppression",
    "columnInfo": [
      {"columnIndex": 0, "originalColumn": "hostname", "keyColumn": true, "columnType": "STRING"},
      {"columnIndex": 1, "originalColumn": "scanner_ip", "keyColumn": false, "columnType": "STRING"},
      {"columnIndex": 2, "originalColumn": "scanner_tool", "keyColumn": false, "columnType": "STRING"},
      {"columnIndex": 3, "originalColumn": "authorized_by", "keyColumn": false, "columnType": "STRING"}
    ]
  }' \
  "${BASE_URL}/dataTables?dataTableId=authorized_scanners_exclusion" || echo "Table may already exist."

echo "==> 3. Creating multi_column_admin_exceptions..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Composite 4-tuple exception table for CodSec/INDA multi-column suppression",
    "columnInfo": [
      {"columnIndex": 0, "originalColumn": "origin_ip", "keyColumn": true, "columnType": "STRING"},
      {"columnIndex": 1, "originalColumn": "target_ip", "keyColumn": true, "columnType": "STRING"},
      {"columnIndex": 2, "originalColumn": "username", "keyColumn": true, "columnType": "STRING"},
      {"columnIndex": 3, "originalColumn": "action", "keyColumn": true, "columnType": "STRING"},
      {"columnIndex": 4, "originalColumn": "exception_reason", "keyColumn": false, "columnType": "STRING"}
    ]
  }' \
  "${BASE_URL}/dataTables?dataTableId=multi_column_admin_exceptions" || echo "Table may already exist."

echo "==> 4. Populating corporate_asset_directory rows..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {"data_table_row": {"values": ["ES01-W10", "ES", "Spain", "TIER_3_WORKSTATION", "Finance", "20"]}},
      {"data_table_row": {"values": ["CH02-SRV", "CH", "Switzerland", "TIER_1_CRITICAL", "Engineering", "80"]}},
      {"data_table_row": {"values": ["US03-LAP", "US", "United States", "TIER_2_PRODUCTION", "Executive", "50"]}},
      {"data_table_row": {"values": ["FR04-SRV", "FR", "France", "TIER_1_CRITICAL", "Engineering", "80"]}},
      {"data_table_row": {"values": ["DE05-W10", "DE", "Germany", "TIER_3_WORKSTATION", "Sales", "20"]}},
      {"data_table_row": {"values": ["GB06-LAP", "GB", "United Kingdom", "TIER_2_PRODUCTION", "Finance", "40"]}}
    ]
  }' \
  "${BASE_URL}/dataTables/corporate_asset_directory/dataTableRows:bulkCreate"

echo "==> 5. Populating authorized_scanners_exclusion rows..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {"data_table_row": {"values": ["scan-sec-01.corp.internal", "10.10.100.15", "Qualys", "SEC-8831"]}},
      {"data_table_row": {"values": ["vuln-check-02.corp.internal", "10.10.100.16", "Nessus", "SEC-9102"]}},
      {"data_table_row": {"values": ["corp-recon-03.corp.internal", "10.10.100.17", "Rapid7", "SEC-9404"]}}
    ]
  }' \
  "${BASE_URL}/dataTables/authorized_scanners_exclusion/dataTableRows:bulkCreate"

echo "==> 6. Populating multi_column_admin_exceptions rows..."
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {"data_table_row": {"values": ["10.0.1.50", "192.168.10.5", "svc_backup_admin", "BACKUP_SYNC", "Scheduled nightly backup"]}},
      {"data_table_row": {"values": ["10.0.1.51", "192.168.10.20", "svc_deployer", "RELEASE_DEPLOY", "Automated CI/CD deployment"]}},
      {"data_table_row": {"values": ["172.16.5.100", "10.200.1.1", "admin_tier1", "SSH_REMOTE_EXEC", "Approved bastion jump"]}}
    ]
  }' \
  "${BASE_URL}/dataTables/multi_column_admin_exceptions/dataTableRows:bulkCreate"

echo "==> Data Table setup complete."
