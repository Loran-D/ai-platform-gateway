import psutil
from fastmcp import FastMCP
from ai_platform_gateway.engine import GuardrailEngine

mcp = FastMCP("AI-Platform-Gateway")
guardrail = GuardrailEngine()

@mcp.tool()
def check_system_metrics() -> str:
    """Returns the current CPU and memory usage of the host server."""
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent

    return f"System metrics - CPU Usaage: {cpu}% | RAM Usage: {memory}%"

@mcp.tool
def execute_platform_command(command: str) -> str:
    """
    Executes a platform command after running it through the security guardrail.
    """
    inspection = guardrail.inspect(command)

    if inspection["status"] == "BLOCKED":
        return f"EXECUTION REJECTED [High Risk Score: {inspection['risk_score']}]: {inspection['reason']}"

    if inspection["status"] == "WARNING":
        return f"EXECUTION HELD FOR AUDIT [MEDIUM Risk Score: {inspection['risk_score']}]: {inspection['reason']}"

    return f"EXECUTION SUCCESS: Command '{command}' verfied and excuted safely."

if __name__ == "__main__":
    print("Starting AI platform Gateway (FastMCP)")
    mcp.run()