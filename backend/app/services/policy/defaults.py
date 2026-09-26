"""Built-in policy. Repositories may override it with cryptonex-policy.yml."""

DEFAULT_POLICY_YAML = """\
policies:
  - rule: reject_md5
    algorithm: MD5
    action: fail
  - rule: reject_des
    algorithm: DES
    action: fail
  - rule: reject_small_rsa
    algorithm: RSA
    max_key_size: 2048
    action: fail
  - rule: warn_rsa
    algorithm: RSA
    action: warn
  - rule: warn_sha1
    algorithm: SHA-1
    action: warn
  - rule: warn_classical_public_key
    security_concern: classical_public_key
    action: warn
  - rule: warn_classical_signature
    security_concern: classical_signature
    action: warn
  - rule: warn_classical_key_exchange
    security_concern: classical_key_exchange
    action: warn
  - rule: allow_aes
    algorithm: AES
    action: allow
  - rule: allow_sha256
    algorithm: SHA-256
    action: allow
"""
