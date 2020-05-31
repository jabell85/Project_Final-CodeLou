# Project_Final-CodeLou

Code Louisville Python Final Project

Overview: Build an application that will scan a local Google Drive for harmful software (i.e. Malware ) using the Virus Total API. Scans will happen every "X" day, once scan has been completed that infomation will be stored into a location on the machine and uploaded to Virus Total API. Between each scan, we will log NEW malware detections as well as show previously "passed" software that now scan as Malware via Virus Total. Any offset between previously passed scans and current failures will show the "lag" between when Virus Scanners both detect a malicious piece of software and the time to upload to various virus definition files.

Program Languages: Python SQLLite

MileStones:

1.Create Repo and Have README flie completed.

2.Have application be able to scan local Google Drive.

3.Once 2 is compelted have it connect to Total Virus API to compare information

4.Retreive infomration from mulitple scans and run them against Total Virus API and graphic results.

!!!!Need to Know!!!!!

Please before you run this program make sure you understand that this will need your Google Drive to be downloaded on the desktop before it can run. This means if you have sensitive information on your Google Drive I suggest that you make a dummy account and download that to test the program. This program is designed to upload all of the information on the Google Drive to the website VirusTotal which will run aganist there database of potential malware.

Once you have downloaded Google Drive to your local machaine make sure you sign up for a free account from VirusTotal to be able to get an API key to be generated. Make sure you copy that key to a Notepad because we will need that later.
When you have a key save on a Notepad go ahead and open up the command prompt and check to see what version of python you are running on your machaine. Python version that this program was made to run off of was version Python 3.8.3 if you havent downloaded Python here is a link https://www.python.org/downloads/release/python-383/ this is for the most lastest version(released 5/13/20).

Once we have Python updated or loaded and the key for VirusTotal we will open the command prompt and link a path to your Google Drive folder on your local machine.

Ex. python ./Final_Pj.py -i C:\Users\name\AppData\Local\Google\Drive\ -o C:\Users\name\Desktop\testfile.txt --apiKey=<YOUR_API_KEY> --dumpOnly --dataDbLoc=C:\Users\name\Desktop (MAKE SURE YOURE IN THE RIGHT DIRECTORY!!!!!) After you put this in the command prompt just hit enter and let the program do what its suppose to do. It will display some a "matplotlib" image, please either save it or exit it when it pops to finish the program
