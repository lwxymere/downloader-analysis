import sys
import json
import os
import csv

'''
This program collates the api or behavioral statistics for each sample in a category, and saves them in a csv file.
Each row in the csv file contains statistics for a sample.
Each column in the csv file will correspond to an api in notableapis.txt or behavior in notablebehaviors.txt, and 
the number of times each api or behavior is used.

Usage: python analyze.py <category> <api / behavior>
Note: <category> is a category of samples (e.g. downloader), which has reports located at basePath/category (e.g. jsons/downloader)
'''

basePath = 'jsons/' # base path where cuckoo reports are saved
networkCols = ['tls','udp','dns_servers','http','icmp','smtp','tcp','smtp_ex','mitm','dns','http_ex','domains','dead_hosts','irc','https_ex']
# hardcoded network signatures that can be found in cuckoo reports

def getApiList():
    apis = []
    with open('notableapis.txt', 'r') as f:
        for line in f:
            apis.append(line.rstrip())
    return apis

def createApiStatsRow(reportName, reportPath, apiList):
    cols = ['sample'] + apiList
    #print(cols)
    row = [reportName] + [0 for i in range(0, len(apiList))]
    with open(reportPath, 'r') as f:
        data = json.load(f)
        if 'behavior' not in data or 'apistats' not in data['behavior']:
            return None
        for pid, apis in data['behavior']['apistats'].items():
            for api, num in apis.items():
                row[cols.index(api)] += num
    #print(row)
    return row

def getBehaviorList():
    behaviors = []
    with open('notablebehaviors.txt', 'r') as f:
        for line in f:
            behaviors.append(line.rstrip())
    return behaviors

def createNetworkStatsRow(data):
    row = []
    for colName in networkCols:
        if colName in data['network']:
            row.append(len(data['network'][colName]))
        else:
            row.append(0)
    return row

def createProcessStatsRow(reportName, reportPath, cols):
    row = [reportName] + [0 for i in range(0, len(cols) - 1)]
    with open(reportPath, 'r') as f:
        data = json.load(f)
        if 'behavior' not in data or 'generic' not in data['behavior']:
            return None
        processes = data['behavior']['generic']
        for process in processes:
            for behavior, arr in process['summary'].items():
                row[cols.index(behavior)] += len(arr)
        if 'buffer' in data:
            row[cols.index('dropped_buffers')] += len(data['buffer'])
        if 'dropped' in data:
            row[cols.index('dropped_files')] += len(data['dropped'])
        row[len(cols) - len(networkCols) : ] = createNetworkStatsRow(data)
    return row

if __name__ == '__main__':
    try:
        category = sys.argv[1]
        switch = sys.argv[2]
    except:
        print('Usage: python analyze.py [ benign / downloader / malware ] [ api / behavior ]')
        sys.exit(0)

    basePath += category
    if switch == 'api':
        with open('apistats-' + category + '.csv', 'w') as f:
            apiList = getApiList()
            cols = ['sample'] + apiList
            writer = csv.writer(f)
            writer.writerow(cols)
            for reportName in os.listdir(basePath):
                reportPath = os.path.join(basePath, reportName)
                print('doing ' + reportName)
                row = createApiStatsRow(reportName, reportPath, apiList)
                if row != None:
                    writer.writerow(row)
    elif switch == 'behavior':
        with open('behaviors-' + category + '.csv', 'w') as f:
            behaviorList = getBehaviorList()
            cols = ['sample'] + behaviorList + ['dropped_buffers', 'dropped_files'] + networkCols
            writer = csv.writer(f)
            writer.writerow(cols)
            for reportName in os.listdir(basePath):
                reportPath = os.path.join(basePath, reportName)
                print('doing ' + reportName)
                processRow = createProcessStatsRow(reportName, reportPath, cols)
                if processRow != None:
                    writer.writerow(processRow)

'''
# --- metadata ---
name = reportName
score = data['info']['score']
sha256 = data['target']['file']['sha256']

# --- dropped buffers ----
numBuffers = len(data['buffer'])

# --- network ---
numTls = len(data['network']['tls'])
numUdp = len(data['network']['udp'])
numDnsServers = len(data['network']['dns_servers'])
numHttp = len(data['network']['http'])
numIcmp = len(data['network']['icmp'])
numSmtp = len(data['network']['smtp'])
numTcp = len(data['network']['tcp'])
numSmtpEx = len(data['network']['smtp_ex'])
numMitm = len(data['network']['mitm'])
numDnsReqs = len(data['network']['dns'])
numHttpEx = len(data['network']['http_ex'])
numDomains = len(data['network']['domains'])
numDeadHosts = len(data['network']['dead_hosts'])
numIrc = len(data['network']['irc'])
numHttpsEx = len(data['network']['https_ex'])

hosts = data['network']['hosts']
domains = data['network']['domains']

# --- signatures ---
# figure out what to do for this, hard to handle
# not sorted by api calls

# --- dropped files --- 
numDroppedFiles = len(data['dropped'])

# --- behaviour ---
behaviors = data['behavior']['generic']
apiStats = data['behavior']['apistats'] # [pid: ['api': num]]
processes = data['behavior']['processes'] # behaviour of malware and its child processes?
'''
