"""Basic usage examples for the Enterprise Risk Assessment System.

This script demonstrates how to use each agent individually and
how to run the complete end-to-end workflow with the supervisor.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.servicenow_agent import ServiceNowAgent
from src.agents.vulnerability_agent import VulnerabilityAgent
from src.agents.threat_agent import ThreatAgent
from src.agents.risk_scoring_agent import RiskScoringAgent
from src.supervisor.supervisor import RiskAssessmentSupervisor


def example_servicenow_query():
    """Example: Query ServiceNow for incidents and assets."""
    print("\n" + "=" * 60)
    print("Example 1: ServiceNow Query Agent")
    print("=" * 60)

    agent = ServiceNowAgent()

    # Natural language query
    response = agent.query("Show me all critical priority incidents")
    print(f"\nResponse:\n{response}")

    # Programmatic access
    incidents = agent.get_incidents_for_analysis(priority="1", limit=5)
    print(f"\nFound {len(incidents)} critical incidents")

    for inc in incidents[:3]:
        print(f"- {inc.number}: {inc.short_description}")


def example_vulnerability_analysis():
    """Example: Analyze CVEs with NVD, VirusTotal, and CISA KEV."""
    print("\n" + "=" * 60)
    print("Example 2: Vulnerability Analysis Agent")
    print("=" * 60)

    agent = VulnerabilityAgent()

    # Analyze single CVE
    cve_id = "CVE-2024-3400"  # Example: PAN-OS command injection
    response = agent.query(f"Analyze {cve_id}")
    print(f"\nResponse:\n{response}")

    # Programmatic analysis
    analyses = agent.analyze_cves([cve_id])
    if analyses:
        analysis = analyses[0]
        print(f"\nCVE: {analysis.cve_detail.cve_id}")
        print(f"CVSS: {analysis.cve_detail.cvss_score} ({analysis.cve_detail.cvss_severity})")
        print(f"In CISA KEV: {analysis.exploitation_status.in_cisa_kev}")
        print(f"Priority: {analysis.priority_score}/100")
        print(f"Recommendation: {analysis.recommendation}")


def example_threat_research():
    """Example: Research threat intelligence for CVEs."""
    print("\n" + "=" * 60)
    print("Example 3: Threat Research Agent")
    print("=" * 60)

    agent = ThreatAgent()

    # Research CVE threat intelligence
    cve_id = "CVE-2024-3400"
    response = agent.query(f"Get threat intelligence for {cve_id}")
    print(f"\nResponse:\n{response}")

    # Programmatic access
    threat_intel = agent.analyze_cve_threat(
        cve_id,
        "OS command injection vulnerability in PAN-OS management interface",
    )
    print(f"\nThreat Intelligence for {threat_intel.cve_id}:")
    print(f"MITRE Techniques: {len(threat_intel.techniques)}")
    print(f"Narrative: {threat_intel.narrative[:200]}...")


def example_risk_scoring():
    """Example: Calculate risk scores with FAIR-based matrix."""
    print("\n" + "=" * 60)
    print("Example 4: Risk Scoring Agent")
    print("=" * 60)

    agent = RiskScoringAgent()

    # Calculate risk
    risk_rating = agent.calculate_risk(
        cve_id="CVE-2024-3400",
        asset_name="firewall-prod-01",
        cvss_score=10.0,
        in_cisa_kev=True,
        vt_detections=15,
        asset_criticality=5,
        data_sensitivity=4,
    )

    print(f"\nRisk Assessment:")
    print(f"CVE: {risk_rating.cve_id}")
    print(f"Asset: {risk_rating.asset_name}")
    print(f"Risk Level: {risk_rating.risk_level}")
    print(f"Risk Score: {risk_rating.risk_score}/25")
    print(f"Likelihood: {risk_rating.likelihood.overall_score}/5")
    print(f"Impact: {risk_rating.impact.overall_score}/5")
    print(f"\nRecommendations:")
    for rec in risk_rating.recommendations:
        print(f"- {rec}")


def example_complete_workflow():
    """Example: Run complete end-to-end risk assessment."""
    print("\n" + "=" * 60)
    print("Example 5: Complete Workflow with Supervisor")
    print("=" * 60)

    supervisor = RiskAssessmentSupervisor()

    # Run assessment with specific CVEs
    result = supervisor.run_assessment(
        query="Assess critical vulnerabilities in production environment",
        cve_ids=["CVE-2024-3400", "CVE-2024-21762"],
    )

    print("\nWorkflow completed!")
    print(f"Analyzed {len(result.get('vulnerabilities', []))} vulnerabilities")
    print(f"Generated {len(result.get('risk_ratings', []))} risk ratings")
    print(f"Report saved to: {result.get('report_path', 'N/A')}")

    print("\nWorkflow Messages:")
    for msg in result.get("messages", []):
        print(f"  {msg}")


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("Enterprise Risk Assessment System - Usage Examples")
    print("=" * 60)

    # Note: These examples require API keys to be configured
    # Check .env file before running

    print("\nNOTE: These examples require API keys configured in .env file")
    print("      Set SKIP_EXAMPLES=1 to skip running live API calls\n")

    if os.getenv("SKIP_EXAMPLES"):
        print("Skipping live examples (SKIP_EXAMPLES=1)")
        return

    # Run examples (comment out as needed)
    try:
        # example_servicenow_query()
        # example_vulnerability_analysis()
        # example_threat_research()
        example_risk_scoring()
        # example_complete_workflow()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("Check your API keys and network connectivity")


if __name__ == "__main__":
    main()
