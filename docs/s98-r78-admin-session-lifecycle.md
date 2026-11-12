# S98-R78 console password session lifecycle candidate

The real HTTP lab proved that logout returned 200 while the same Sanctum bearer
could still administer Navigator. The public logout route has no sanctum auth
middleware; Laravel SessionGuard::logout did not revoke the personal access token.
The candidate deletes exactly the bearer presented, clears its session/bootstrap
caches, then logs out and invalidates an attached session if one exists.

Password login now creates an expires_at value. Default is 120 minutes, bounded
between 1 and 1440 via CONSOLE_TOKEN_TTL_MINUTES and capped by a shorter configured
Sanctum expiration. Inactive accounts and expired/old authToken reuse cannot bypass
password authentication. No database migration or active-environment change.

Proof: companion FleetOps delivery branch feature/s98-r78-navigator-v2-delivery,
security-tests/r78-http-lab.py, R78-HTTP-RESULT.json and R78-SOURCE-SHA256.json.
33/33 actual wire HTTP checks under Laravel 12.71.0 / PHP 8.2.35, identity-empty
R29 archive migrated 395→398, MySQL 8, phpredis and two HTTP containers on a private
network. Positive admin login, QR/proof/approval/final claim, tenant isolation,
Origin/cookie-CSRF rejection, logout then same bearer 401, expired bearer 401,
expired authToken 401, inactive login 401, revoke and Redis cross-process limiter
pass. App Unit 52/200 and FleetOps controller/routes 16/124 pass separately.
No mock is labelled HTTP acceptance, and no real secrets are printed.

Scope limit: SSO/2FA/invite/impersonation issuance and legacy unbounded tokens still
need a centralized lifecycle policy before release. Existing tokens are not
silently purged from an active database. This commit does not claim full console
MFA acceptance, Android, Firebase or QA/production deployment.

Source confidentiality scan found no key/token-shaped values in these changes.
Exact commit CI is a separate gate. Production and active QA remain unchanged;
PR Fleet #11 is draft, V2 off outside disposable memory, release NO-GO.
