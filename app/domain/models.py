from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class AutonomyLevel(str, Enum):
    OBSERVE="L0_OBSERVE"; RECOMMEND="L1_RECOMMEND"; APPROVAL="L2_APPROVAL_REQUIRED"; BOUNDED="L3_BOUNDED_AUTONOMOUS"
class Status(str, Enum):
    NEW="NEW"; EVIDENCE="EVIDENCE"; PLANNED="PLANNED"; WAITING_APPROVAL="WAITING_APPROVAL"; EXECUTING="EXECUTING"; VERIFYING="VERIFYING"; SUCCEEDED="SUCCEEDED"; ROLLED_BACK="ROLLED_BACK"; ESCALATED="ESCALATED"
@dataclass(frozen=True)
class Evidence:
    source: str; key: str; value: Any
@dataclass(frozen=True)
class PatchPlan:
    plan_id: str; host_id: str; cve: str; package: str; from_version: str; to_version: str; production: bool; blast_radius: int; rollback_available: bool
@dataclass
class WorkflowResult:
    run_id: str; status: Status; autonomy: AutonomyLevel; evidence: list[Evidence]=field(default_factory=list); events: list[dict]=field(default_factory=list); message: str=""
    def pretty(self):
        lines=[f"Run: {self.run_id}",f"Status: {self.status.value}",f"Autonomy: {self.autonomy.value}","Evidence:"]
        lines += [f"  - {e.source}: {e.key}={e.value}" for e in self.evidence]
        lines += ["Trajectory:"]+[f"  {i+1:02d}. {e['event']} | {e.get('detail','')}" for i,e in enumerate(self.events)]
        lines += [f"Outcome: {self.message}"]
        return "\n".join(lines)
