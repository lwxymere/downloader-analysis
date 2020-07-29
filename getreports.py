from pathlib import Path
from shutil import copyfile

'''
This program copies all new reports that do not already exist at REPORT_DST_PATH/<category>, 
where <category> is a category in reportDirCategories, to REPORT_DST_PATH.
The copied reports have to be manually sorted, so this program is best used when new cuckoo analyses
fall under the same category (e.g. all new analyses are downloader samples), before analysing 
samples of another category.

Usage: python getreports.py
'''

CUCKOO_ANALYSES_PATH = '/home/chaoscold/.cuckoo/storage/analyses' # path where cuckoo stores analysis results
REPORT_DST_PATH = '/home/chaoscold/reports' # destination directory to store reports

reportDirs = Path(CUCKOO_ANALYSES_PATH)
reportDirCategories = ['benign', 'downloader', 'malware']

def reportExists(reportName):
    for cat in reportDirCategories:
        path = Path(REPORT_DST_PATH + '/' + cat + '/' + name + '.json')
        if path.exists():
            return True
    return False

num_copied = 0
for reportDir in reportDirs.iterdir():
    name = reportDir.name
    src = CUCKOO_ANALYSES_PATH + '/' + name + '/reports/report.json'
    dst = REPORT_DST_PATH + '/' + name + '.json'
    if reportExists(name)  or name == 'latest':
        #print(dst + ' exists, skipping...')
        continue
    else:
        print('creating ' +  dst)
        try:
            copyfile(src, dst)
            num_copied += 1
        except:
            print('----- SKIPPED -----')
            pass # skip if no report.json found, e.g. for .gitignore folder
print(str(num_copied) + ' new reports added')
