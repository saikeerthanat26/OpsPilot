from datetime import datetime, timezone
class Trace:
    def __init__(self): self.events=[]
    def add(self,event,detail="",**attrs): self.events.append({"ts":datetime.now(timezone.utc).isoformat(),"event":event,"detail":detail,**attrs})
