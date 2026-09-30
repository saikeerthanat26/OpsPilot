from app.domain.models import Evidence
class DiagnosticAgent:
    def __init__(self, tools): self.tools=tools
    def run(self, host):
        h=self.tools.get_host_health(host)
        return [Evidence("metrics",k,v) for k,v in h.items()]
