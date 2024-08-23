import tomllib
import sys

file="alert_example.toml"
with open(file,"rb") as toml:
    alert=tomllib.load(toml)

#print(alert)

"""
for table in alert:
    print(table)
"""

"""
for table in alert:
    for field in alert[table]:
        print(field)
"""
"""
for field in alert['rule']:
    print(field)

"""
present_fields=[]
missing_fields=[]

if alert['rule']['type']=="query":
    required_fields=['description','name','risk_score','severity','type','query']

elif alert['rule']['type']="eql": # event correlation alert
    required_fields=['description','name','risk_score','severity','type','query','language']

elif alert['rule']['type']="threshold": # threshold based alert
    required_fields=['description','name','risk_score','severity','type','query','threshold']


for table in alert:
    for field in alert[table]:
        present_fields.append(field)

for field in required_fields:
    if field not in present_fields:
        missing_fields.append(field)

    if missing_fields:
        print("The following fields do not exist in " + file + ": " + str(missing_fields))
    else:
        print("Validation passed for: " + file)

