# Google SecOps: Data Table Left Outer Joins, Anti-Joins, and Multi-Column Tuple Suppressions

This repository provides canonical reproduction suites, schemas, datasets, and YARA-L detection rules validating **Left Outer Join** (`#dt >= 0`), **Anti-Join / Exclusion** (`#dt = 0`), and **Multi-Column Composite Tuple Suppressions** in Google Security Operations (Malachite / Chronicle).

---

## Background & Problem Statement

Historically, YARA-L rule evaluation against Data Tables defaulted to strict **Inner Join** semantics:
- **Inner Join Event Dropping**: Unmatched events whose join keys did not exist in the Data Table were silently dropped from the detection stream. For enrichment use cases (e.g., enriching authentication events with asset tier or country code), unmanaged devices or new endpoints vanished instead of emitting default or null values.
- **Anti-Join / Exclusion Failures**: When practitioners attempted exclusion patterns via `condition: $e AND #dt = 0`, the legacy compiler's predicate analysis failed to normalize Data Table query ID prefixes when populating `AllowEventNull`. This caused the join generator to emit `AllowEmpty: false` (inner join) instead of `AllowEmpty: true` (outer join), resulting in zero matches.
- **Multi-Column Workarounds**: For composite multi-field exclusions, teams had to concatenate fields with custom delimiters (`strings.concat($src, "|", $dst, ...)`) and run expensive regex checks (`re.regex`).

### Key References

- **Community Articles**:
  - [Data Table Event Enrichment: Inner vs Left vs Outer](https://security.googlecloudcommunity.com/google-security-operations-2/data-table-event-enrichment-inner-vs-left-vs-outer-6712)
  - [How Soon is Null: Using IOCs with Outer Joins](https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-how-soon-is-null-using-iocs-with-outer-joins-7129)


---

## Repository Structure

```
.
├── data/
│   ├── corporate_asset_directory.csv       # Country, tier, and risk score enrichment dataset
│   ├── authorized_scanners_exclusion.csv   # Vulnerability scanner hostname exclusion dataset
│   └── multi_column_admin_exceptions.csv   # 4-tuple composite exception dataset
├── rules/
│   ├── case1_left_outer_join.yaral         # Left outer join test cases (inner drop, #dt >= 0, native)
│   ├── case2_anti_join.yaral               # Anti-join test cases (#dt = 0 condition, count workaround)
│   └── case3_multi_column_tuple_anti_join.yaral # Clean multi-column row tuple anti-join
└── scripts/
    └── deploy_tenant_artifacts.sh          # REST API automation script to provision tables and rows
```

---

## Reference Data Tables

### 1. `corporate_asset_directory`
Enrichment table for hostnames providing asset classification and geographic location.

- **Data File**: [`data/corporate_asset_directory.csv`](data/corporate_asset_directory.csv)
- **Schema**:
  | Column | Type | Key Column | Description |
  | :--- | :--- | :--- | :--- |
  | `hostname` | `STRING` | **Yes** | Hostname used as the primary join key |
  | `country_code` | `STRING` | No | Two-letter ISO country code |
  | `country_name` | `STRING` | No | Full country name |
  | `asset_tier` | `STRING` | No | Criticality level (`TIER_1_CRITICAL`, `TIER_2_PRODUCTION`, `TIER_3_WORKSTATION`) |
  | `owner_dept` | `STRING` | No | Owning business unit |
  | `risk_score` | `NUMBER` | No | Risk score value (0–100) |

- **Sample Records**:
  | hostname | country_code | country_name | asset_tier | owner_dept | risk_score |
  | :--- | :--- | :--- | :--- | :--- | :--- |
  | `ES01-W10` | `ES` | Spain | `TIER_3_WORKSTATION` | Finance | 20 |
  | `CH02-SRV` | `CH` | Switzerland | `TIER_1_CRITICAL` | Engineering | 80 |
  | `US03-LAP` | `US` | United States | `TIER_2_PRODUCTION` | Executive | 50 |
  | `FR04-SRV` | `FR` | France | `TIER_1_CRITICAL` | Engineering | 80 |
  | `DE05-W10` | `DE` | Germany | `TIER_3_WORKSTATION` | Sales | 20 |
  | `GB06-LAP` | `GB` | United Kingdom | `TIER_2_PRODUCTION` | Finance | 40 |

---

### 2. `authorized_scanners_exclusion`
Single-key exclusion table containing authorized vulnerability scanner hostnames.

- **Data File**: [`data/authorized_scanners_exclusion.csv`](data/authorized_scanners_exclusion.csv)
- **Schema**:
  | Column | Type | Key Column | Description |
  | :--- | :--- | :--- | :--- |
  | `hostname` | `STRING` | **Yes** | Authorized scanner hostname |
  | `scanner_ip` | `STRING` | No | Static source IP of the scanner |
  | `scanner_tool` | `STRING` | No | Scanner product (`Qualys`, `Nessus`, `Rapid7`) |
  | `authorized_by` | `STRING` | No | Approval ticket or security engineer reference |

- **Sample Records**:
  | hostname | scanner_ip | scanner_tool | authorized_by |
  | :--- | :--- | :--- | :--- |
  | `scan-sec-01.corp.internal` | `10.10.100.15` | Qualys | SEC-8831 |
  | `vuln-check-02.corp.internal` | `10.10.100.16` | Nessus | SEC-9102 |
  | `corp-recon-03.corp.internal` | `10.10.100.17` | Rapid7 | SEC-9404 |

---

### 3. `multi_column_admin_exceptions`
Composite multi-column exception table matching exact 4-tuples: `(origin_ip, target_ip, username, action)`.

- **Data File**: [`data/multi_column_admin_exceptions.csv`](data/multi_column_admin_exceptions.csv)
- **Schema**:
  | Column | Type | Key Column | Description |
  | :--- | :--- | :--- | :--- |
  | `origin_ip` | `STRING` | **Yes** | Source IP address |
  | `target_ip` | `STRING` | **Yes** | Destination IP address |
  | `username` | `STRING` | **Yes** | Service account or admin user |
  | `action` | `STRING` | **Yes** | Specific administrative action or product event type |
  | `exception_reason` | `STRING` | No | Business context and change justification |

- **Sample Records**:
  | origin_ip | target_ip | username | action | exception_reason |
  | :--- | :--- | :--- | :--- | :--- |
  | `10.0.1.50` | `192.168.10.5` | `svc_backup_admin` | `BACKUP_SYNC` | Scheduled nightly backup |
  | `10.0.1.51` | `192.168.10.20` | `svc_deployer` | `RELEASE_DEPLOY` | Automated CI/CD deployment |
  | `172.16.5.100` | `10.200.1.1` | `admin_tier1` | `SSH_REMOTE_EXEC` | Approved bastion jump |

---

## Rules & Detection Logic

### Case 1: Left Outer Join & Event Preservation (`rules/case1_left_outer_join.yaral`)

Demonstrates the contrast between default inner join behavior, standard production left outer join syntax, and native common compiler syntax.

#### Rule 1A: Inner Join Drop Failure (`dt_left_outer_join_01_inner_drop_failure`)
- **Purpose**: Demonstrates the failure mode. If an authentication event originates from a host not present in `corporate_asset_directory`, the event is dropped and no detection is generated.
- **Syntax**: Condition uses `#corporate_asset_directory > 0` (or implicit inner join).

```yaral
rule dt_left_outer_join_01_inner_drop_failure {
  meta:
    author = "Kyle Champlin"
    description = "Demonstrates inner-join event drop: drops events whose hostname is not in the data table"
  events:
    $e.principal.hostname != ""
    $hostname = $e.principal.hostname

    // Direct inner join against Data Table
    $hostname = %corporate_asset_directory.hostname

  match:
       $hostname over 1h

  outcome:
    $country = array_distinct(%corporate_asset_directory.country_code)
    $asset_tier = array_distinct(%corporate_asset_directory.asset_tier)
    $risk_score = max(%corporate_asset_directory.risk_score)

  condition:
    $e  AND #corporate_asset_directory > 0
}
```

#### Rule 1B: Standard Left Outer Join via `#dt >= 0` (`dt_left_outer_join_02_standard_enrichment`)
- **Purpose**: Production standard for zero event loss. Preserves 100% of the event stream. Unmatched events receive default fallback values using `strings.coalesce` or conditional expressions.
- **Key Mechanism**: Cardinality constraint `#corporate_asset_directory >= 0` forces the compiler to set `AllowEmpty: true`.

```yaral
rule dt_left_outer_join_02_standard_enrichment {
  meta:
    author = "Kyle Champlin"
    description = "Standard Left Outer Join using #dt >= 0: preserves 100% of events and populates enrichment fields"
  events:
    $e.principal.hostname != ""
    $hostname = $e.principal.hostname

    // Outer join equality binding
    $hostname = %corporate_asset_directory.hostname

  match:
    $hostname over 1h

  outcome:
    $country = array_distinct(strings.coalesce(%corporate_asset_directory.country_code, "UNKNOWN"))
    $asset_tier = array_distinct(strings.coalesce(%corporate_asset_directory.asset_tier, "UNMANAGED"))
    $risk_score = max(if(%corporate_asset_directory.risk_score > 0, %corporate_asset_directory.risk_score, 0))

  condition:
    $e AND #corporate_asset_directory >= 0
}
```

#### Rule 1C: Native Declarative Left Join (`dt_left_outer_join_03_common_compiler_native`)
- **Purpose**: Target syntax for the Common Compiler. Uses explicit `left join` keyword in the `events` section.
- **Caveat**: Common compiler is still rolling out to select customers as of Sept 2026

```yaral
rule dt_left_outer_join_03_common_compiler_native {
  meta:
    author = "Kyle Champlin"
    description = "Native declarative LEFT JOIN syntax for Common Compiler. Common compiler is still rolling out"
  events:

    $hostname = $e.principal.hostname

    left join $hostname = %corporate_asset_directory.hostname

  match:
    $hostname over 1h

  outcome:
    $country = array_distinct(strings.coalesce(%corporate_asset_directory.country_code, "UNKNOWN"))
    $asset_tier = array_distinct(strings.coalesce(%corporate_asset_directory.asset_tier, "UNMANAGED"))
    $risk_score = max(if(%corporate_asset_directory.risk_score > 0, %corporate_asset_directory.risk_score, 0))

  condition:
    $e
}
```

---

### Case 2: Anti-Join / Exclusion (`rules/case2_anti_join.yaral`)

Suppresses alerts when an event matches an entry in an exclusion table, while triggering when no match exists.

#### Rule 2A: Native Anti-Join via `#dt = 0` (`dt_anti_join_01_nonexistence_condition`)
- **Purpose**: Verifies the fix from CL 966198411 / b/541376003. When `#authorized_scanners_exclusion = 0`, the engine executes an anti-join, emitting a detection only when the host is NOT in the exclusion table.

```yaral
rule dt_anti_join_01_nonexistence_condition {
  meta:
    author = "Kyle Champlin"
    description = "Anti-join exclusion list using #dt = 0: triggers alert ONLY if host is NOT in authorized scanner table"
  events:

    $e.principal.hostname = ""
    $hostname = $e.principal.hostname

    // Bind join key to Data Table
    $hostname = %authorized_scanners_exclusion.hostname

  match:
    $hostname over 1h

  outcome:
    $total_sent_bytes = sum($e.network.sent_bytes)

  condition:
    $e AND #authorized_scanners_exclusion = 0
}
```

#### Rule 2B: Outcome Aggregation Count Workaround (`dt_anti_join_02_outcome_count_workaround`)
- **Purpose**: Documents the fallback pattern used prior to the `#dt = 0` compiler fix. Uses outcome aggregation `count(%table.hostname)` evaluated in the condition.

```yaral
rule dt_anti_join_02_outcome_count_workaround {
  meta:
    author = "Kyle Champlin"
    description = "Anti-join via outcome variable count check: triggers when scanner match count is zero"
  events:

    $hostname = $e.principal.hostname

    $hostname = %authorized_scanners_exclusion.hostname

  match:
    $hostname over 1h

  outcome:
    $total_sent_bytes = sum($e.network.sent_bytes)
    $scanner_match_count = count(%authorized_scanners_exclusion.hostname)


  condition:
    $e AND $scanner_match_count = 0
    // alternative that also enforced a anti join: #authorized_scanners_exclusion = 0
    // that example is shown in rule dt_anti_join_01_nonexistence_condition
}
```

## Semantics & Compiler Cheat Sheet

| Join Pattern | YARA-L Event Syntax | YARA-L Condition | Compiler Internal Flag | Behavior on Unmatched Events |
| :--- | :--- | :--- | :--- | :--- |
| **Inner Join** | `$key = %dt.key` | `$e AND #dt > 0` | `AllowEmpty: false` | Event is **dropped** |
| **Left Outer Join** | `$key = %dt.key` | `$e AND #dt >= 0` | `AllowEmpty: true` | Event is **preserved**; table fields are null |
| **Declarative Left Join** | `left join $key = %dt.key` | `$e` | `AllowEmpty: true` | Event is **preserved**; table fields are null |
| **Anti-Join (Exclusion)** | `$key = %dt.key` | `$e AND #dt = 0` | `AllowEmpty: true` | Alerts **only** when key does NOT exist in table |
| **Tuple Anti-Join** | `$k1 = %dt.c1` ... `$k4 = %dt.c4` | `$e AND #dt = 0` | `AllowEmpty: true` | Alerts **only** when composite tuple does NOT match |

### Outcome Variable Handling for Outer Joins
When an event does not match a Data Table row in an outer join, referencing `%dt.column` directly in aggregations or functions will yield null:
- **Strings**: Use `strings.coalesce(%dt.column, "DEFAULT_VALUE")`.
- **Numbers**: Use `if(%dt.score > 0, %dt.score, 0)` or `coalesce` before aggregation to avoid null propagation.

---

## Deployment & Verification

Deploy datasets and schemas to any Chronicle / Google SecOps tenant using the provisioning script:

```bash
# 1. Authenticate with Google Cloud
gcloud auth application-default print-access-token

# 2. Run automated table schema creation and bulk row ingestion
bash scripts/deploy_tenant_artifacts.sh
```

