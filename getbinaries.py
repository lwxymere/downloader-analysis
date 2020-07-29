from pathlib import Path
from shutil import copyfile
import sys
import json

''' 
This program copies a selected category's (e.g. downloader) binaries from the cuckoo binaries directory to a destination of choice, to store binaries by category.
Only binaries that have reports in COLLATED_REPORTS_PATH/category will be copied

Usage: python getbinaries.py <category>
'''

CUCKOO_BINARIES_PATH = '/home/chaoscold/.cuckoo/storage/binaries' # path where cuckoo automatically saves analysed binaraies
COLLATED_REPORTS_PATH = '/home/chaoscold/reports' # base path where reports are stored
DST_BINARIES_PATH = '/home/chaoscold/binaries' # destination directory to store the binaries

reportDirCategories = ['benign', 'downloader', 'malware'] # names of directories where reports are stored

def binExists(binName, cat):
    path = Path(DST_BINARIES_PATH + '/' + cat + '/' + binName)
    if path.exists():
        return True
    return False

# --- main ---
category = sys.argv[1] # benign / downloader / malware, which binaries to collect

reports_src = Path(COLLATED_REPORTS_PATH + '/' + category)
binaries_src = Path(CUCKOO_BINARIES_PATH)
binaries_dst = Path(DST_BINARIES_PATH + '/' + category)

if not (reports_src.exists() and binaries_src.exists() and binaries_dst.exists()):
    print('Usage: python getbinaries.py <category>')
    print('Categories: ' + str(reportDirCategories))
    sys.exit(0)

print('preparing to move ' + category + ' binaries')

sha256_list = set()
for report in reports_src.iterdir():
    with open(report, 'r') as f:
        data = json.load(f)
        sha256_list.add(data['target']['file']['sha256'])

print('found ' + str(len(sha256_list)) + ' reports for ' + category)

num_copied = 0
for binary in binaries_src.iterdir():
    sha256 = binary.name.split('.')[0] # handle file extensions like .bin
    if sha256 in sha256_list and not binExists(binary.name, category):
        #print('copying ' + binary.name)
        src = CUCKOO_BINARIES_PATH + '/' + binary.name
        dst = DST_BINARIES_PATH + '/' + category + '/' + binary.name
        try:
            copyfile(src, dst)
            num_copied += 1
        except:
            print('error copying ' + binary.name)
            pass

print(str(num_copied) + ' new binaries added')


