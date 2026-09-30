from app.domain.models import AutonomyLevel, PatchPlan
class PolicyEngine:
    def classify(self, plan: PatchPlan, confidence: float):
        if plan.production: return AutonomyLevel.APPROVAL
        if plan.blast_radius > 1 or confidence < .90: return AutonomyLevel.APPROVAL
        if plan.rollback_available: return AutonomyLevel.BOUNDED
        return AutonomyLevel.RECOMMEND
    def authorize(self, plan, approved: bool):
        level=self.classify(plan,.94)
        return level, (approved if level==AutonomyLevel.APPROVAL else level==AutonomyLevel.BOUNDED)
