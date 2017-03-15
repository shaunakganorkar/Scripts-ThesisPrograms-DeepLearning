#python script for extracting JSON strings from cuckoo sandbox output
#An object with string containing multiple string:value pairs (nested string:value pairs) <== This is our struggle


import json
from pprint import pprint
with open('/home/shaunak/Desktop/Scripts/report.json') as json_file:
    data = json.load(json_file)

info_monitor = (str(data['info']['monitor']))
info_machine_name = (str(data['info']['machine']['name']))

virustotal_normalized = (str(data['virustotal']['normalized']))
virustotal_sha256 = (str(data['virustotal']['sha256']))

static_pdb_path = (str(data['static']['pdb_path']))

#strings = (str(data['strings']))

#pprint (str(data['static']['pe_imports']['imports'][4]))
#pprint (str(data['behavior']['summary']))
#pprint (str(data['strings']))
#print info_monitor
#print info_machine_name
#print virustotal_normalized
#behavior_generic = (str(data['behavior']['generic'][0]))





write_in_file = open('resultFile.txt','w')
write_in_file.write(virustotal_sha256 +'\n'+ info_machine_name + '\n' + info_monitor + '\n')
write_in_file.write(static_pdb_path + '\n')
#write_in_file.write()
to_dict = data
for item in to_dict['behavior']['generic']:
    behavior_generic = str(item['summary'])
    
    write_in_file.write(behavior_generic)

    #print behavior_generic                                       #<====== I need to write this on a file. However it says TypeError: expected a string or other character buffer object


#write_in_file.write('\n'+'\n'+ strings + '\n')

write_in_file.close()