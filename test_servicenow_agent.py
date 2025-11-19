import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from agents.servicenow_agent import ServiceNowAgent

print("Testing ServiceNow Agent...")
print("=" * 60)

try:
    # Initialize agent
    print("\n1. Initializing ServiceNow Agent...")
    agent = ServiceNowAgent()
    print("✅ Agent initialized successfully")
    
    # Test query
    print("\n2. Testing agent query...")
    query = "Show me the top 3 incidents"
    result = agent.query(query)
    
    print("✅ Query successful!")
    print("\nAgent Response:")
    print("-" * 60)
    print(result)
    print("-" * 60)
    
    print("\n🎉 ServiceNow Agent is working correctly!")
    
except Exception as e:
    print(f"\n❌ Error: {str(e)}")
    import traceback
    traceback.print_exc()
