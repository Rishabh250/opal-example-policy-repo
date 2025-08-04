package api.authz

import future.keywords.in
import future.keywords.every

# By default, deny access.
default allow = false

allow {
    # Manual JWT payload decoding (base64 decode the middle part)
    parts := split(input.token, ".")
    payload := json.unmarshal(base64url.decode(parts[1]))
    
    # Check the claims manually
    payload.aud[_] == "platform"
    payload.iss == "abc merchant"
}