# downloader-analysis
Samples and code used for SIP

## Prerequisites
* Create a base directory where all cuckoo reports will be stored, sorted by categories (e.g. benign, downloaders, malware). Each category should be a sub-directory.

## Workflow
1. Analyse samples from a single category, then run **getreports.py**, which will copy all new cuckoo reports to the base directory. Then, move these copied reports to their respective sub-directory to sort them manually.
2. When all reports have been copied, **getbinaries.py** can be used to copy and automatically sort the analysed binaries by category. The name of each binary should be the sha256 hash of the binary.
3. Before analysing the reports, run **getapicalls.py** and **getgenericbehaviors.py** to generate the files *notableapis.txt* and *notablebehaviors.txt* to collate all unique api calls and behaviors observed across all samples.
4. Run **analyze.py** with various arguments to generate csv files containing the statistics of api calls and behaviors for each category.

## Samples Used
Zipped binaries can be found at https://gofile.io/d/kMeTCD (password: infected)
> Warning - these are actual malware samples, do not download unless certain
