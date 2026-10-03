"""
SentinelAI: Self-improving, multi-agent autonomous SOC investigation tier.
"""
from sentinelai.interfaces.feedback import record_feedback
from sentinelai.interfaces.rl_client import FileRLClient, RLClient
from sentinelai.investigation import investigate
from sentinelai.schemas import AnalystFeedback, IncidentInput, InvestigationReport

__all__ = [
    "investigate",
    "record_feedback",
    "InvestigationReport",
    "AnalystFeedback",
    "IncidentInput",
    "RLClient",
    "FileRLClient",
]
