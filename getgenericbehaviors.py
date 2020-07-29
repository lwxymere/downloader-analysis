import json
import os

'''
This program goes through the cuckoo JSON reports and finds all unique behaviors shown by all samples,
then saves them in notablebehaviors.txt
'''
basePath = 'jsons/' # base path where cuckoo json reports are saved

behaviors = set()
for category in os.listdir(basePath):
    reportDirPath = os.path.join(basePath, category)
    for report in os.listdir(reportDirPath):
        reportPath = os.path.join(reportDirPath, report)
        print('reading ' + report)
        with open(reportPath, 'r') as f:
            data = json.load(f)
            if 'behavior' in data and 'generic' in data['behavior']:
                processes = data['behavior']['generic']
                for process in processes:
                    for behavior in process['summary'].keys():
                        behaviors.add(behavior)

#for behavior in sorted(behaviors):
#    print(behavior)
with open('notablebehaviors.txt', 'w') as f:
    for behavior in sorted(behaviors):
        f.write(behavior + '\n')
