package api.authz

import future.keywords.in
import future.keywords.every

# By default, deny access.
default allow = false

allow {
    # Decode JWT without signature verification (for testing)
    [_, _, claims] := io.jwt.decode(input.token)

    # Continue with other policy rules, using the `claims` object.
    check_claims(claims)
}

# A separate rule to contain the more specific checks.
check_claims(claims) {
    claims.aud == "your-api-audience"
    claims.iss == "https://your-identity-provider.com"
}