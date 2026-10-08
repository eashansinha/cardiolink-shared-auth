# cardiolink-shared-auth

Shared HMAC/JWT helpers used by the CardioLink device gateway and clinician portal.

`verify_token(token)` validates HS256 tokens signed with the shared service secret
(`CARDIOLINK_HS_SECRET`). Used across services so a clinician session issued by the
portal is trusted by the gateway.
