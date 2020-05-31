Need to Know
1. Please before you run this program make sure you understand that this will need your Google Drive to be downloaded on the desktop before it can run. This means if you have sensitive information on your Google Drive I suggest that you make a dummy account and download that to test the program. This program is designed to upload all of the information on the Google Drive to the website VirusTotal which will run aganist there database of potential malware.

2. Once you have downloaded Google Drive to your local machaine make sure you sign up for a free account from VirusTotal to be able to get an API key to be generated. Make sure you copy that key to a Notepad because we will need that later.

3. When you have a key save on a Notepad go ahead and open up the command prompt and check to see what version of python you are running on your machaine. Python version that this program was made to run off of was version Python 3.8.3 if you havent downloaded Python here is a link https://www.python.org/downloads/release/python-383/ this is for the most lastest version(released 5/13/20).

4. Once we have Python updated or loaded and the key for VirusTotal we will open the command prompt and link a path to your Google Drive folder on your local machine.  
Ex. python ./Final_Pj.py -i C:\Users\name\AppData\Local\Google\Drive\ -o C:\Users\name\Desktop\testfile.txt --apiKey=<YOUR_API_KEY> --dumpOnly --dataDbLoc=C:\Users\name\Desktop
After you put this in the command prompt just hit enter and let the program do what its suppose to do. It will display some a "matplotlib" image, please either save it or exit it when it pops to finish the program