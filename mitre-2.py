import requests
import os
import tomllib
url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers= {
        'accept': 'application/json'
        }

mitredata=requests.get(url,headers=headers).json()
mitreMapped={}

# def getMapping(mitredata)

for object in mitredata['objects']:
    tactics=[]
    if object['type']=='attack-pattern':
        if 'external_references' in object:
            for reference in object['external_references']:
                if 'external_id' in reference:
                    if((reference['external_id'].startswith("T"))):
                        if 'kill_chain_phases' in object:
                            for tactic in object['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                        technique=reference['external_id']
                        name=object['name']
                        url=reference['url']
                        # print(technique+ " : " + name + " : " + str(tactics))

                        
                        if 'x_mitre_deprecated' in object:
                            deprecated=object['x_mitre_deprecated']
                            filtered_object={'tactics':str(tactics),'technique':technique,'name':name,'url':url,'deprecated':deprecated}
                            mitreMapped[technique]=filtered_object
                        else:
                            filtered_object={'tactics':str(tactics),'technique':technique,'name':name,'url':url,'deprecated':"False"}
                            mitreMapped[technique]=filtered_object


alert_data = {}
for root,dirs,files in os.walk("/home/trevorphilips/Desktop/Coding/python/tcm-detection-engineering/custom_alerts"):
    for file in files:
        if file.endswith(".toml"):
            full_path=os.path.join(root,file)
            with open(full_path,"rb") as toml:
                alert=tomllib.load(toml)
                filtered_object_array=[]
                
                if alert['rule']['threat'][0]['framework']=="MITRE ATT&CK":
                    for threat in alert['rule']['threat']:
                        technique_id=threat['technique'][0]['id']
                        technique_name=threat['technique'][0]['name']
                        
                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic="none"
                        
                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id=threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name=threat['technique'][0]['subtechnique'][0]['name']

                        else:
                            subtechnique_id="none"
                            subtechnique_name="none"

                        filtered_object={'tactic':tactic,'technique_id':technique_id,"technique_name":technique_name,"subtechnique_id":subtechnique_id,"subtechnique_name":subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file]=filtered_object_array


print(alert_data)

'''
print(mitreMapped['T1123']['name'])
print('\n')
print(mitreMapped['T1144'])
'''


