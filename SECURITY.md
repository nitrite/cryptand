# Security policy

## Supported versions

| version | supported |
|---|---|
| 1.0.x (Rust, Java, Dart) | yes |
| < 1.0 | no |

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on
[nitrite/cryptand](https://github.com/nitrite/cryptand/security/advisories/new).
Do not open a public issue.

Include the implementation (Rust, Java, Dart) and version, and if you can a
file or op sequence that reproduces it. A hostile `.cryptand` file is the most
useful form.

- Acknowledgement within 3 working days, a first assessment within 10.
- A fix is checked in all three implementations before release.
- We coordinate the disclosure date with you; 90 days is the default ceiling.
  Credit is given in the advisory unless you ask otherwise.

## Scope

In scope: anything that breaks the guarantees of `spec/14-security.md` (encryption,
integrity, nonce uniqueness, key handling) or lets a crafted file cause a
crash, hang, unbounded allocation or wrong read in any implementation.

Out of scope: an attacker who already holds the key or password; side
channels on shared hardware; denial of service by a writer with legitimate
access. See `reference/SECURITY-REVIEW.md` for the threat model.
