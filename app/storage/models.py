from sqlalchemy import Column, Float, MetaData, Table, Text

metadata = MetaData()
runs = Table("runs", metadata,
    Column("run_id", Text, primary_key=True), Column("tenant_id", Text),
    Column("status", Text), Column("autonomy", Text), Column("payload", Text),
    Column("created_at", Text), Column("updated_at", Text))
approval_grants = Table("approval_grants", metadata,
    Column("grant_id", Text, primary_key=True), Column("token_hash", Text, unique=True, nullable=False),
    Column("run_id", Text, nullable=False), Column("tenant_id", Text, nullable=False),
    Column("plan", Text, nullable=False), Column("executor_id", Text, nullable=False),
    Column("approver", Text, nullable=False), Column("expires_at", Float, nullable=False))
operations = Table("operations", metadata,
    Column("run_id", Text, primary_key=True), Column("capability", Text, primary_key=True),
    Column("grant_id", Text, nullable=False), Column("status", Text, nullable=False))
host_leases = Table("host_leases", metadata,
    Column("tenant_id", Text, primary_key=True), Column("host_id", Text, primary_key=True),
    Column("run_id", Text, unique=True, nullable=False))
inventory = Table("inventory", metadata,
    Column("host_id", Text, primary_key=True), Column("tenant_id", Text, nullable=False),
    Column("provider", Text, nullable=False), Column("payload", Text, nullable=False))
snapshots = Table("snapshots", metadata,
    Column("run_id", Text, primary_key=True), Column("host_id", Text, primary_key=True),
    Column("payload", Text, nullable=False))
receipts = Table("backend_receipts", metadata,
    Column("run_id", Text, primary_key=True), Column("capability", Text, primary_key=True),
    Column("payload", Text, nullable=False))
operation_results = Table("operation_results", metadata,
    Column("run_id", Text, primary_key=True), Column("capability", Text, primary_key=True),
    Column("payload", Text, nullable=False))
audit = Table("audit_events", metadata,
    Column("event_id", Text, primary_key=True), Column("run_id", Text, nullable=False, index=True),
    Column("tenant_id", Text, nullable=False), Column("payload", Text, nullable=False))

workers = Table("execution_workers", metadata,
    Column("run_id", Text, primary_key=True), Column("owner", Text, nullable=False),
    Column("expires_at", Float, nullable=False))
