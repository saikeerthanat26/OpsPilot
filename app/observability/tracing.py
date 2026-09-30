from datetime import datetime, timezone
class Trace:
    def __init__(self, sink=None): self.events=[]; self.sink=sink
    def add(self,event,detail="",**attrs):
        item={"ts":datetime.now(timezone.utc).isoformat(),"event":event,"detail":detail,**attrs}
        if self.sink: self.sink(item)
        self.events.append(item)
