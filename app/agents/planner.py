import uuid
from app.domain.models import PatchPlan
class RemediationPlanner:
    def __init__(self, tools): self.tools=tools
    def plan(self,host,cve):
        h=self.tools.get_host_health(host); p=self.tools.get_patch_metadata(host)
        return PatchPlan(str(uuid.uuid4()),host,cve,p["package"],p["from_version"],p["to_version"],h["environment"]=="production",1,p.get("rollback_available",True))
