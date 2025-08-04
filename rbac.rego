package api.authz

import future.keywords.in
import future.keywords.every

# By default, deny access.
default allow = false

allow {
    # Decode and verify the JWT. This function checks the signature.
    [verified, _, claims] := io.jwt.decode_verify(input.token, {"cert": data.jwks})

    # The token must be verified.
    verified == true

    # The token must not be expired.
    # The `nbf` (not before) and `exp` (expiration) claims are checked automatically by decode_verify if time is provided.
    # To check them manually, you can compare the claims with the current time.
    # For example, using a manual check for expiration:
    # time.now_ns() < claims.exp * 1000000000

    # Continue with other policy rules, using the `claims` object.
    check_claims(claims)
}

# A separate rule to contain the more specific checks.
check_claims(claims) {
    claims.aud == "your-api-audience"
    claims.iss == "https://your-identity-provider.com"
}