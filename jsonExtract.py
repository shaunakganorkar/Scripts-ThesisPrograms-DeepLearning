#python script for extracting JSON strings from cuckoo sandbox output
#An object with string containing multiple string:value pairs (nested string:value pairs) <== This is our struggle

import os
import json
from pprint import pprint
with open('/home/shaunak/Desktop/Scripts/report.json') as json_file:
    data = json.load(json_file)

info_monitor = (str(data['info']['monitor']))
info_machine_name = (str(data['info']['machine']['name']))

virustotal_normalized = (str(data['virustotal']['normalized']))
virustotal_sha256 = (str(data['virustotal']['sha256']))

static_pdb_path = (str(data['static']['pdb_path']))

write_in_file = open('resultFile.txt','w')
write_in_file.write(virustotal_sha256 +'\n'+ info_machine_name + '\n' + info_monitor + '\n')
write_in_file.write(static_pdb_path + '\n')
#write_in_file.write()
to_dict = data
for item in to_dict['behavior']['generic']:
    behavior_generic = str(item['summary'])
    
    write_in_file.write(behavior_generic)

#write_in_file.write('\n'+'\n'+ strings + '\n')

to_dict = data
for item in to_dict['static']['pe_imports']:
    static_pe_imports = str(item['imports'])
    
    write_in_file.write('\n'+static_pe_imports+'\n')
write_in_file.close()


with open('resultFile.txt', 'r') as file :
  filedata = file.read()

# Replace the target string
filedata = filedata.replace("u'name': u'", '')
filedata = filedata.replace("u'address': u'", '')
filedata = filedata.replace('{', '')
filedata = filedata.replace('}', '')
filedata = filedata.replace('[', '')
filedata = filedata.replace(']', '')
filedata = filedata.replace("'", '')

# Write the file out again
with open('filteredResult.txt', 'w') as file:
  file.write(filedata)

os.remove("/home/shaunak/Desktop/Scripts/resultFile.txt")
