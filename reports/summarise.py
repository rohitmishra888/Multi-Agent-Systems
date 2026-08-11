import json

with open('reports/catalog.json') as f:
    cat = json.load(f)

print('=== SCAN METADATA ===')
m = cat['metadata']
print(f"Target       : {m['target_url']}")
print(f"OpenAPI URL  : {m['openapi_url']}")
print(f"Started      : {m['scan_started_at']}")
print(f"Completed    : {m['scan_completed_at']}")
print()

print('=== STATISTICS ===')
s = cat['statistics']
print(f"Total Endpoints : {s['total_endpoints']}")
print(f"Auth Required   : {s['authenticated_endpoints']}")
print(f"No Auth         : {s['unauthenticated_endpoints']}")
print()
print('By Method:')
for method, count in sorted(s['by_method'].items()):
    print(f"  {method:<10}: {count}")
print()
print('By Category:')
for cat_name, count in sorted(s['by_category'].items()):
    print(f"  {cat_name:<30}: {count}")
print()
print('By Risk:')
for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
    count = s['by_risk'].get(risk, 0)
    if count:
        print(f"  {risk:<10}: {count}")
print()
print('By Discovery Method:')
for disc, count in sorted(s['by_discovery_method'].items()):
    print(f"  {disc:<30}: {count}")

print()
print('=== ENDPOINT INVENTORY ===')
for ep in cat['endpoints']:
    auth = 'AUTH' if ep['authentication_required'] else 'OPEN'
    cat_label = ep['category']
    via = ep['discovered_by']
    line = f"  [{ep['risk']:<8}] {ep['method']:<8} {ep['endpoint']:<47} [{auth}] [{cat_label}] (via {via})"
    print(line)
