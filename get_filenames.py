import os
for root,dirs,files in os.walk("/home/trevorphilips/Desktop/Coding/python/tcm-detection-engineering/custom_alerts"):
    for file in files:
        if file.endswith(".toml"):
            print(file)

    
