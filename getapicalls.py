import json
import os

'''
This program goes through the cuckoo JSON reports and finds all unique API calls made by all samples,
then saves them in notableapis.txt
'''
basePath = 'jsons/' # base path where cuckoo reports are saved

apis = set()
for category in os.listdir(basePath):
    reportDirPath = os.path.join(basePath, category)
    for report in os.listdir(reportDirPath):
        reportPath = os.path.join(reportDirPath, report)
        print('reading ' + report)
        with open(reportPath, 'r') as f:
            data = json.load(f)
            if 'behavior' in data and 'apistats' in data['behavior']:
                apistats = data['behavior']['apistats']
                for pid, calls in apistats.items():
                    for apiName, num in calls.items():
                        apis.add(apiName)

with open('notableapis.txt', 'w') as f:
    for api in sorted(apis):
        f.write(api + '\n')
