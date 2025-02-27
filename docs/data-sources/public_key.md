---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "tls_public_key Data Source - terraform-provider-tls"
subcategory: ""
description: |-
  Get a public key from a PEM-encoded private key.
  Use this data source to get the public key from a PEM (RFC 1421) https://datatracker.ietf.org/doc/html/rfc1421 or OpenSSH PEM (RFC 4716) https://datatracker.ietf.org/doc/html/rfc4716 formatted private key, for use in other resources.
---

# tls_public_key (Data Source)

Get a public key from a PEM-encoded private key.

Use this data source to get the public key from a [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) or [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formatted private key, for use in other resources.

## Example Usage

```terraform
resource "tls_private_key" "ed25519-example" {
  algorithm = "ED25519"
}

# Public key loaded from a terraform-generated private key, using the PEM (RFC 1421) format
data "tls_public_key" "private_key_pem-example" {
  private_key_pem = tls_private_key.ed25519-example.private_key_pem
}

# Public key loaded from filesystem, using the Open SSH (RFC 4716) format
data "tls_public_key" "private_key_openssh-example" {
  private_key_openssh = file("~/.ssh/id_rsa_rfc4716")
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `private_key_openssh` (String, Sensitive) The private key (in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format) to extract the public key from. This is _mutually exclusive_ with `private_key_pem`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`.
- `private_key_pem` (String, Sensitive) The private key (in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format) to extract the public key from. This is _mutually exclusive_ with `private_key_openssh`. Currently-supported algorithms for keys are: `RSA`, `ECDSA`, `ED25519`.

### Read-Only

- `algorithm` (String) The name of the algorithm used by the given private key. Possible values are: `RSA`, `ECDSA`, `ED25519`.
- `id` (String) Unique identifier for this data source: hexadecimal representation of the SHA1 checksum of the data source.
- `openssh_comment` (String) The OpenSSH comment.
- `public_key_fingerprint_md5` (String) The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the selected private key format is compatible, as per the rules for `public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations).
- `public_key_fingerprint_sha256` (String) The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. Only available if the selected private key format is compatible, as per the rules for `public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations).
- `public_key_fingerprint_x509_sha256` (String) The SHA256 hash of the binary key data, encoded as a base64 string
- `public_key_openssh` (String) The public key, in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format. This is also known as ['Authorized Keys'](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace).
- `public_key_pem` (String) The public key, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. **NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) [libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this value append a `\n` at the end of the PEM. In case this disrupts your use case, we recommend using [`trimspace()`](https://www.terraform.io/language/functions/trimspace).
