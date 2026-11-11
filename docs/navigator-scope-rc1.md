# Navigator scope integration contract

The RC1 Navigator patch adds nullable server-owned purpose/issuer columns to API
credentials and a nullable pairing reference to Sanctum tokens. Existing keys
retain their ordinary authentication behavior; new Navigator keys require the
matching FleetOps issuance, route restrictions and migrations. Never deploy the
core and FleetOps changes separately.

Navigator principals cannot access or hold console sessions. Bootstrap keys
have a strict action/method allowlist, active tenant-bound device and issuer,
and a mandatory seven-day maximum lifetime. Paired driver tokens must resolve
their active parent key on every request. Pairing credentials and passwords are
excluded from API and model activity audit payloads. Ordinary expired API keys
are rejected before OPTIONS handling as well.

The migration's backward operation refuses to remove scope metadata while
Navigator credentials or sessions exist. See FleetOps
`docs/navigator-pairing-rc1.md` for lifecycle, limitations and rollback gates.
Runtime integration tests are maintained in Fleet's
`api/tests/Feature/Rc1NavigatorMySqlTest.php` against the exact application lock
and disposable MySQL, not a simplified model replacement.
