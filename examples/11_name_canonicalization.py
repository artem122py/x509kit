"""11 - DN canonicalization (RFC 4518).

Run: python examples/11_name_canonicalization.py
"""
from x509kit import Name, names_equal

CASES = [
    ("case",         {"CN": "Example.COM"},     {"CN": "example.com"}),
    ("spaces",       {"CN": "My  Org"},         {"CN": "my org"}),
    ("fullwidth",    {"CN": "\uFF21\uFF22\uFF23"}, {"CN": "abc"}),
    ("ligature",     {"CN": "\uFB01le"},        {"CN": "file"}),
    ("different",    {"CN": "alice"},           {"CN": "bob"}),
    ("RDN order",    {"C": "XX", "O": "Org"},   {"O": "Org", "C": "XX"}),
]

print("DN canonicalization examples:")
print()
for label, a, b in CASES:
    na = Name.from_dict(a)
    nb = Name.from_dict(b)
    raw_eq = na.raw == nb.raw
    canon_eq = names_equal(na, nb)
    marker = "same" if canon_eq else "different"
    print(f"  {label:12s}  raw={raw_eq!s:5s}  canonical={canon_eq!s:5s}  -> {marker}")
    print(f"    A: {na}")
    print(f"    B: {nb}")
    print()
