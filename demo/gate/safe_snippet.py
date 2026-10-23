"""Controlled SAFE half of the demo pair: computes a sum and writes a marker file."""
import os
total = sum(range(10))
with open(os.path.join(os.environ.get('CODEGUARD_DEMO_OUT', '.'), 'marker_safe.txt'), 'w') as f:
    f.write(f'safe snippet ran, total={total}')
