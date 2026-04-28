"""
core/filter.py
Utility to filter out low-severity findings from raw scan results.
"""

RELEVANT_SEVERITIES = {"medium", "high", "critical"}


def remove_noise(raw_results: list[dict]) -> list[dict]:
    """
    Filter raw scan results, keeping only findings with actionable severity.

    Args:
        raw_results: List of finding dicts, each expected to have a 'severity' key.

    Returns:
        Filtered list containing only items whose 'severity' is
        'medium', 'high', or 'critical' (case-insensitive).
    """
    if not isinstance(raw_results, list):
        raise TypeError(f"Expected list, got {type(raw_results).__name__}")

    filtered: list[dict] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        severity = item.get("severity", "").lower().strip()
        if severity in RELEVANT_SEVERITIES:
            filtered.append(item)

    return filtered
