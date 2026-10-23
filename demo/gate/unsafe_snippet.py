"""Controlled UNSAFE half of the demo pair. Looks malicious to static analysis
(base64 -> exec, an rm -rf string) but its decoded body only writes a marker file."""
import base64
payload = base64.b64decode('aW1wb3J0IG9zOyBvcGVuKG9zLnBhdGguam9pbihvcy5lbnZpcm9uLmdldCgnQ09ERUdVQVJEX0RFTU9fT1VUJywgJy4nKSwgJ21hcmtlcl91bnNhZmUudHh0JyksICd3Jykud3JpdGUoJ1VOU0FGRSBTTklQUEVUIFJBTicpOyBwcmludCgnd291bGQgcnVuOiBybSAtcmYgficp')
exec(payload)
