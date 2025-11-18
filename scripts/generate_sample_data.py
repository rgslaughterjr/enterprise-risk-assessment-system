#!/usr/bin/env python3
"""
Generate Sample Data for Enterprise Risk Assessment System

This script generates realistic mock data for demos and testing:
- CVE records with CVSS scores
- Security controls
- ServiceNow incidents
- Threat intelligence
- Risk assessments
- Compliance documents

Usage:
    python scripts/generate_sample_data.py --output data/samples/
    python scripts/generate_sample_data.py --format json --count 100
"""

import json
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from faker import Faker
except ImportError:
    print("Installing faker...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "faker"])
    from faker import Faker


fake = Faker()


# ============================================================================
# CVE DATA GENERATION
# ============================================================================

def generate_cve_id(year: int = None) -> str:
    """Generate realistic CVE ID."""
    if year is None:
        year = random.randint(2020, 2024)
    sequence = random.randint(1000, 99999)
    return f"CVE-{year}-{sequence}"


def generate_cve_record() -> Dict[str, Any]:
    """Generate a realistic CVE record."""
    cve_id = generate_cve_id()
    cvss_score = round(random.uniform(0.1, 10.0), 1)

    # CVSS severity based on score
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # CWE categories (common weakness enumerations)
    cwe_options = [
        "CWE-79: Cross-site Scripting (XSS)",
        "CWE-89: SQL Injection",
        "CWE-20: Improper Input Validation",
        "CWE-78: OS Command Injection",
        "CWE-22: Path Traversal",
        "CWE-352: Cross-Site Request Forgery",
        "CWE-94: Code Injection",
        "CWE-434: Unrestricted File Upload",
        "CWE-287: Improper Authentication",
        "CWE-862: Missing Authorization"
    ]

    # Vulnerability types
    vuln_types = [
        "Remote Code Execution",
        "SQL Injection",
        "Cross-Site Scripting",
        "Authentication Bypass",
        "Privilege Escalation",
        "Information Disclosure",
        "Denial of Service",
        "Memory Corruption",
        "Path Traversal",
        "Command Injection"
    ]

    # Affected products
    products = [
        "Apache Struts", "Microsoft Exchange", "VMware vCenter",
        "Cisco IOS", "Fortinet FortiOS", "Palo Alto PAN-OS",
        "Oracle WebLogic", "Adobe Acrobat", "Jenkins",
        "WordPress", "Drupal", "Joomla"
    ]

    published_date = fake.date_between(start_date='-2y', end_date='today')

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_severity": severity,
        "description": f"{random.choice(vuln_types)} vulnerability in {random.choice(products)} "
                      f"allows remote attackers to {fake.sentence()}",
        "published_date": published_date.isoformat(),
        "last_modified": (published_date + timedelta(days=random.randint(1, 30))).isoformat(),
        "cwe": random.choice(cwe_options),
        "vector_string": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "in_cisa_kev": random.random() < 0.15,  # 15% in CISA KEV
        "exploited_in_wild": random.random() < 0.08,  # 8% exploited
        "patch_available": random.random() < 0.85,  # 85% have patches
        "affected_product": random.choice(products),
        "vendor": random.choice(["Microsoft", "Apache", "Cisco", "VMware", "Oracle", "Adobe"])
    }


def generate_cve_batch(count: int = 50) -> List[Dict[str, Any]]:
    """Generate a batch of CVE records."""
    return [generate_cve_record() for _ in range(count)]


# ============================================================================
# SECURITY CONTROLS GENERATION
# ============================================================================

def generate_security_control() -> Dict[str, Any]:
    """Generate a security control based on NIST 800-53."""

    # NIST 800-53 control families
    control_families = {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "AT": "Awareness and Training",
        "CM": "Configuration Management",
        "CP": "Contingency Planning",
        "IA": "Identification and Authentication",
        "IR": "Incident Response",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PS": "Personnel Security",
        "PE": "Physical Protection",
        "PL": "Planning",
        "RA": "Risk Assessment",
        "CA": "Security Assessment",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SA": "System and Services Acquisition"
    }

    family_code = random.choice(list(control_families.keys()))
    control_number = random.randint(1, 25)
    control_id = f"{family_code}-{control_number}"

    implementation_status = random.choice([
        "Implemented", "Partially Implemented", "Planned", "Not Implemented"
    ])

    effectiveness = random.choice([
        "Effective", "Partially Effective", "Ineffective", "Unknown"
    ])

    return {
        "control_id": control_id,
        "control_family": control_families[family_code],
        "control_name": f"{control_families[family_code]} Control {control_number}",
        "description": fake.paragraph(nb_sentences=3),
        "implementation_status": implementation_status,
        "effectiveness": effectiveness,
        "responsible_party": fake.name(),
        "last_assessment_date": fake.date_between(start_date='-1y', end_date='today').isoformat(),
        "next_assessment_date": fake.date_between(start_date='today', end_date='+1y').isoformat(),
        "control_type": random.choice(["Preventive", "Detective", "Corrective", "Deterrent"]),
        "automation_level": random.choice(["Manual", "Semi-Automated", "Fully Automated"]),
        "evidence": [f"Evidence document {i+1}" for i in range(random.randint(1, 4))]
    }


def generate_controls_batch(count: int = 30) -> List[Dict[str, Any]]:
    """Generate a batch of security controls."""
    return [generate_security_control() for _ in range(count)]


# ============================================================================
# SERVICENOW INCIDENTS GENERATION
# ============================================================================

def generate_incident() -> Dict[str, Any]:
    """Generate a ServiceNow incident record."""

    incident_types = [
        "Security Incident", "Service Outage", "Performance Issue",
        "Configuration Change", "Access Request", "Vulnerability Remediation"
    ]

    priorities = ["1 - Critical", "2 - High", "3 - Medium", "4 - Low", "5 - Planning"]
    states = ["New", "In Progress", "On Hold", "Resolved", "Closed"]
    categories = [
        "Network", "Server", "Application", "Security",
        "Database", "Endpoint", "Cloud Infrastructure"
    ]

    created_date = fake.date_time_between(start_date='-90d', end_date='now')

    # Generate number based on date
    incident_number = f"INC{created_date.strftime('%Y%m%d')}{random.randint(1000, 9999)}"

    return {
        "number": incident_number,
        "short_description": f"{random.choice(incident_types)}: {fake.sentence()}",
        "description": fake.paragraph(nb_sentences=5),
        "priority": random.choice(priorities),
        "state": random.choice(states),
        "category": random.choice(categories),
        "assigned_to": fake.name(),
        "assignment_group": random.choice([
            "Security Operations", "Network Engineering", "Application Support",
            "Infrastructure Team", "Cloud Operations"
        ]),
        "caller": fake.name(),
        "opened_at": created_date.isoformat(),
        "resolved_at": (created_date + timedelta(hours=random.randint(1, 72))).isoformat()
                       if random.random() > 0.3 else None,
        "impact": random.choice(["1 - High", "2 - Medium", "3 - Low"]),
        "urgency": random.choice(["1 - High", "2 - Medium", "3 - Low"]),
        "affected_ci": f"{random.choice(['srv', 'app', 'db', 'fw'])}-{fake.word()}-{random.randint(1, 99):02d}",
        "close_notes": fake.paragraph() if random.random() > 0.5 else None
    }


def generate_incidents_batch(count: int = 40) -> List[Dict[str, Any]]:
    """Generate a batch of ServiceNow incidents."""
    return [generate_incident() for _ in range(count)]


# ============================================================================
# ASSETS / CMDB GENERATION
# ============================================================================

def generate_asset() -> Dict[str, Any]:
    """Generate a CMDB asset record."""

    asset_types = [
        "Server", "Firewall", "Router", "Switch", "Load Balancer",
        "Database", "Application Server", "Web Server", "Storage Array"
    ]

    environments = ["Production", "Staging", "Development", "QA", "DR"]
    operating_systems = [
        "Windows Server 2019", "Windows Server 2022", "RHEL 8",
        "Ubuntu 22.04", "CentOS 7", "VMware ESXi 7.0"
    ]

    asset_type = random.choice(asset_types)
    asset_name = f"{asset_type.lower().replace(' ', '-')}-{fake.word()}-{random.randint(1, 99):02d}"

    return {
        "name": asset_name,
        "asset_type": asset_type,
        "asset_tag": f"AT-{random.randint(100000, 999999)}",
        "serial_number": fake.bothify(text='??###??####').upper(),
        "ip_address": fake.ipv4_private(),
        "hostname": f"{asset_name}.{fake.domain_name()}",
        "operating_system": random.choice(operating_systems),
        "environment": random.choice(environments),
        "criticality": random.choice(["Critical", "High", "Medium", "Low"]),
        "business_service": random.choice([
            "E-Commerce Platform", "Customer Portal", "Internal Apps",
            "Financial Systems", "HR Systems", "Email Services"
        ]),
        "location": fake.city(),
        "managed_by": fake.name(),
        "purchase_date": fake.date_between(start_date='-5y', end_date='-1y').isoformat(),
        "warranty_expiration": fake.date_between(start_date='today', end_date='+3y').isoformat(),
        "cost_center": f"CC-{random.randint(1000, 9999)}",
        "status": random.choice(["Active", "Inactive", "Maintenance", "Decommissioned"])
    }


def generate_assets_batch(count: int = 50) -> List[Dict[str, Any]]:
    """Generate a batch of CMDB assets."""
    return [generate_asset() for _ in range(count)]


# ============================================================================
# THREAT INTELLIGENCE GENERATION
# ============================================================================

def generate_threat_intelligence() -> Dict[str, Any]:
    """Generate threat intelligence data."""

    threat_actors = [
        "APT28 (Fancy Bear)", "APT29 (Cozy Bear)", "Lazarus Group",
        "Carbanak", "FIN7", "DarkSide", "REvil", "Conti"
    ]

    mitre_techniques = [
        "T1078 - Valid Accounts",
        "T1190 - Exploit Public-Facing Application",
        "T1566 - Phishing",
        "T1053 - Scheduled Task/Job",
        "T1059 - Command and Scripting Interpreter",
        "T1068 - Exploitation for Privilege Escalation",
        "T1003 - OS Credential Dumping",
        "T1021 - Remote Services",
        "T1105 - Ingress Tool Transfer",
        "T1486 - Data Encrypted for Impact"
    ]

    return {
        "threat_id": f"THREAT-{fake.date_this_year().strftime('%Y%m%d')}-{random.randint(1000, 9999)}",
        "threat_name": fake.catch_phrase(),
        "threat_actor": random.choice(threat_actors),
        "target_sectors": random.sample([
            "Financial", "Healthcare", "Government", "Energy",
            "Technology", "Retail", "Manufacturing"
        ], k=random.randint(2, 4)),
        "mitre_techniques": random.sample(mitre_techniques, k=random.randint(3, 6)),
        "iocs": {
            "ip_addresses": [fake.ipv4() for _ in range(random.randint(2, 5))],
            "domains": [fake.domain_name() for _ in range(random.randint(2, 4))],
            "file_hashes": [fake.sha256() for _ in range(random.randint(1, 3))]
        },
        "first_observed": fake.date_between(start_date='-6m', end_date='today').isoformat(),
        "last_observed": fake.date_between(start_date='-30d', end_date='today').isoformat(),
        "confidence": random.choice(["High", "Medium", "Low"]),
        "severity": random.choice(["Critical", "High", "Medium", "Low"]),
        "description": fake.paragraph(nb_sentences=4),
        "recommendations": [fake.sentence() for _ in range(random.randint(3, 5))]
    }


def generate_threats_batch(count: int = 25) -> List[Dict[str, Any]]:
    """Generate a batch of threat intelligence records."""
    return [generate_threat_intelligence() for _ in range(count)]


# ============================================================================
# RISK ASSESSMENTS GENERATION
# ============================================================================

def generate_risk_assessment() -> Dict[str, Any]:
    """Generate a risk assessment record."""

    likelihood = random.randint(1, 5)
    impact = random.randint(1, 5)
    risk_score = likelihood * impact

    # Map score to risk level
    if risk_score >= 20:
        risk_level = "Critical"
    elif risk_score >= 12:
        risk_level = "High"
    elif risk_score >= 6:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "assessment_id": f"RA-{fake.date_this_year().strftime('%Y%m')}-{random.randint(100, 999)}",
        "assessment_date": fake.date_between(start_date='-3m', end_date='today').isoformat(),
        "risk_scenario": fake.sentence(),
        "threat_source": random.choice([
            "External Attackers", "Malicious Insiders", "Natural Disasters",
            "System Failures", "Third-Party Vendors", "Nation-State Actors"
        ]),
        "vulnerability": fake.sentence(),
        "asset_affected": generate_asset()["name"],
        "likelihood": likelihood,
        "likelihood_rationale": fake.paragraph(nb_sentences=2),
        "impact": impact,
        "impact_rationale": fake.paragraph(nb_sentences=2),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "current_controls": [generate_security_control()["control_id"] for _ in range(random.randint(2, 5))],
        "control_effectiveness": random.choice(["Effective", "Partially Effective", "Ineffective"]),
        "residual_risk": random.choice(["Acceptable", "Review Required", "Unacceptable"]),
        "mitigation_plan": fake.paragraph(nb_sentences=3),
        "owner": fake.name(),
        "review_date": fake.date_between(start_date='today', end_date='+6m').isoformat()
    }


def generate_risk_assessments_batch(count: int = 30) -> List[Dict[str, Any]]:
    """Generate a batch of risk assessments."""
    return [generate_risk_assessment() for _ in range(count)]


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main function to generate sample data."""
    parser = argparse.ArgumentParser(
        description="Generate sample data for Enterprise Risk Assessment System"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/samples",
        help="Output directory for generated data"
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "txt"],
        default="json",
        help="Output format"
    )
    parser.add_argument(
        "--cves",
        type=int,
        default=50,
        help="Number of CVE records to generate"
    )
    parser.add_argument(
        "--controls",
        type=int,
        default=30,
        help="Number of security controls to generate"
    )
    parser.add_argument(
        "--incidents",
        type=int,
        default=40,
        help="Number of incidents to generate"
    )
    parser.add_argument(
        "--assets",
        type=int,
        default=50,
        help="Number of assets to generate"
    )
    parser.add_argument(
        "--threats",
        type=int,
        default=25,
        help="Number of threat intelligence records to generate"
    )
    parser.add_argument(
        "--assessments",
        type=int,
        default=30,
        help="Number of risk assessments to generate"
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducibility"
    )

    args = parser.parse_args()

    # Set random seed if provided
    if args.seed:
        random.seed(args.seed)
        Faker.seed(args.seed)

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating sample data in {output_dir}/")
    print("=" * 60)

    # Generate data
    datasets = {
        "cves": (generate_cve_batch(args.cves), "CVE records"),
        "controls": (generate_controls_batch(args.controls), "Security controls"),
        "incidents": (generate_incidents_batch(args.incidents), "ServiceNow incidents"),
        "assets": (generate_assets_batch(args.assets), "CMDB assets"),
        "threats": (generate_threats_batch(args.threats), "Threat intelligence"),
        "risk_assessments": (generate_risk_assessments_batch(args.assessments), "Risk assessments")
    }

    # Write data to files
    for filename, (data, description) in datasets.items():
        output_file = output_dir / f"{filename}.json"

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"✓ Generated {len(data):3d} {description:25s} → {output_file}")

    # Generate summary
    summary = {
        "generated_at": datetime.utcnow().isoformat(),
        "seed": args.seed,
        "counts": {
            name: len(data) for name, (data, _) in datasets.items()
        },
        "total_records": sum(len(data) for data, _ in datasets.values())
    }

    summary_file = output_dir / "summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    print("=" * 60)
    print(f"✓ Total records generated: {summary['total_records']}")
    print(f"✓ Summary saved to: {summary_file}")
    print("\nSample data ready for demos and testing!")


if __name__ == "__main__":
    main()
