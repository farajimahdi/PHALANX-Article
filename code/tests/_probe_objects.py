"""Probe IPImen deeper: IPServices IDs, action codes, more rules."""
from pathlib import Path
import xml.etree.ElementTree as ET

BASE = Path('e:/Projects/Article-FWPolicy/PHALANX/Real-Dataset/anonymized')
tree = ET.parse(BASE / 'ipimen_rules.xml')
root = tree.getroot()

# IPServices with IDs
print("=== IPServices (with Id) ===")
svc_list = root.find("list[@name='IPServices']")
for item in svc_list:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    print(f"  Id={vals.get('Id')!r}  Name={vals.get('Name')!r}  Value={vals.get('Value')!r}")

# Sample more rules to see variety
print("\n=== TrafficRules sample (rules 10-15) ===")
rules_list = root.find("list[@name='TrafficRules']")
all_rules = list(rules_list)
for item in all_rules[9:15]:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    print(f"  Id={vals.get('Id')} Name={vals.get('Name')!r}")
    for k in ('Action','Zone','Src','Dst','Srv','Application','Enabled','SrcOption','DstOption'):
        if k in vals:
            print(f"    {k}: {vals[k]!r}")

# Check all unique Action values
print("\n=== All Action values ===")
actions = set()
for item in all_rules:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    actions.add(vals.get('Action'))
print(f"  {sorted(actions)}")

# Check all unique Src/Dst patterns
print("\n=== Src patterns (unique prefixes) ===")
src_patterns = set()
for item in all_rules:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    s = vals.get('Src', '') or ''
    prefix = s.split(':')[0] if ':' in s else s
    src_patterns.add(prefix)
print(f"  {sorted(src_patterns)}")

print("\n=== Srv patterns (unique prefixes) ===")
srv_patterns = set()
for item in all_rules:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    s = vals.get('Srv', '') or ''
    prefix = s.split(':')[0] if ':' in s else s
    srv_patterns.add(prefix)
print(f"  {sorted(srv_patterns)}")

# IPAccesses - check type=0 (host) vs type=1 (subnet) vs others
print("\n=== IPAccesses type distribution ===")
ip_list = root.find("list[@name='IPAccesses']")
types = {}
for item in ip_list:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    v = vals.get('Value', '') or ''
    t = 'unknown'
    if 'type=0' in v: t = 'host'
    elif 'type=1' in v: t = 'subnet'
    elif 'type=2' in v: t = 'range'
    elif 'type=3' in v: t = 'group'
    types[t] = types.get(t, 0) + 1
print(f"  {types}")

# Show a type=3 (group) example
print("\n=== IPAccesses group examples (type=3) ===")
for item in ip_list:
    vals = {v.get('name'): v.text for v in item.findall('variable')}
    v = vals.get('Value', '') or ''
    if 'type=3' in v:
        print(f"  {vals.get('Name')!r} -> {v!r}")
        break
