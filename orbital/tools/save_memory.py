"""A tool for saving a structured incident summary to memory."""

from google.adk.memory import MemoryService
import json


def save_incident_summary(
    memory_service: MemoryService,
    alert_id: str,
    final_disposition: str,
    key_iocs: list[str],
    response_actions: list[str],
    summary: str
) -> str:
    """
    Saves a structured summary of a completed incident investigation to memory.

    This tool is used by the SOC Manager agent at the end of an investigation
    to persist the final conclusions for future reference via the `load_memory` tool.

    Args:
        memory_service: The ADK MemoryService instance (injected by the runner).
        alert_id: The unique identifier of the alert.
        final_disposition: The final verdict (e.g., 'True Positive', 'False Positive').
        key_iocs: A list of the most critical Indicators of Compromise.
        response_actions: A list of the recommended or executed response actions.
        summary: A brief, natural-language summary of the incident.

    Returns:
        A confirmation message indicating the result of the save operation.
    """
    if not all([alert_id, final_disposition, summary]):
        return "Error: alert_id, final_disposition, and summary are required fields."

    try:
        # Create a unique, searchable key for this incident summary.
        memory_key = f"incident_summary:{alert_id}"

        # Structure the data into a JSON object for clean storage and retrieval.
        memory_value = json.dumps({
            "alert_id": alert_id,
            "final_disposition": final_disposition,
            "key_iocs": key_iocs,
            "response_actions": response_actions,
            "summary": summary
        }, indent=2)

        # Use the memory service to add the record.
        memory_service.add_memory(key=memory_key, value=memory_value)

        return f"Successfully saved incident summary for alert '{alert_id}' to memory."
    except Exception as e:
        # Log the exception if a logger is available, or return a detailed error.
        return f"Error saving incident summary for alert '{alert_id}': {e}"