from pydantic import BaseModel, ConfigDict, Field


class HostArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host_id: str = Field(min_length=1, max_length=128)


class PatchArguments(HostArguments):
    to_version: str = Field(min_length=1, max_length=128)


CONTRACTS = {
    "get_host_health": HostArguments,
    "list_vulnerabilities": HostArguments,
    "get_patch_metadata": HostArguments,
    "execute_approved_patch": PatchArguments,
    "verify_host_health": HostArguments,
    "rollback_patch": HostArguments,
}
