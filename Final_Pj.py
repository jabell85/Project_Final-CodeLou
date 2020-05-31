from datetime import date
import getopt
import glob
import json
import sqlite3
import sys
import time
import urllib
import uuid
import matplotlib.pyplot as plt
from urllib import request
from urllib.error import HTTPError, URLError

# local variables
driveLocation = ''
outputFile = ''
output = []
APIKey = None
verbose = False  # default will be false
dumpOnly = False  # dumpOnly the values from the Google Drive table, not scanning on VT
defaultTimeout = 62  # 60 second timeout for VirusTotal per 4 requests, but give or take another second
VTRescanURL = 'https://www.virustotal.com/vtapi/v2/file/rescan'  # VirusTotal rescan URL
Databases = ["cloud_graph.db", "snapshot.db"]  # Databases we care about
Tables = ["cloud_entry", "cloud_graph_entry"]  # Tables we care about
FILENAME = 0
SIZE = 1
CHECKSUM = 2
dataTableScanType = 'daily'
dataTableLocation =  '' # Location of Google Drive will force to find location of the Drive
dataTableConnection = None


# Program usage
def usage():
    print(
        "Final_Pj.py -i <driveLocation> -o <outputFile> -a <apiKey> -s <daily|weekly> [--apiKey, -d[umpOnly], -v[erbose], --dataDbLoc, --scanType]")

def connectDataTable(): # Data table for Scans
    global dataTableConnection # Gets Gobal Data connection variable
    dataTableConnection = sqlite3.connect(
        dataTableLocation + '/' + 'ScansData.db')  # Creating a new database and naming it

    if dataTableConnection is None:
        print("Unable to get connection the data table, exiting.")
        usage()
        exit(1)
def connect(dbName, tables):
    # connect to the SQLite database and get a cursor
    conn = sqlite3.connect(dbName)
    cursor = conn.cursor()
    # lets loop through and do the tables.
    for table in tables:
        doesExist = cursor.execute("SELECT name FROM sqlite_master WHERE type ='table' AND name='" + table + "';")
        if len(doesExist.fetchall()) == 0: #Loop will get information from Google Drive Databases
            continue

        # get everything from the table
        result = cursor.execute("SELECT filename, size, checksum FROM " + table + ";")# This gets information from the databases
        rows = result.fetchall() # stores informations from Google Drive in rows

        # inform the user how many minutes this will take
        minutesToComplete = ((len(rows) / 4) * defaultTimeout) / 60
        print("It will take roughly. {} minutes to complete".format(minutesToComplete)) #notify's user how long it will take to send to VirusTotal

        count = 0
        index = 1  # root is 0
        while index < len(rows):
            tempOutput = []
            # skip over "Folders", as they don't contain checksums
            if rows[index][CHECKSUM] is None:
                index += 1
                continue
            # The VirusTotal 4 request per minute restriction
            if count == 4 and dumpOnly == False: #count reps successful uploads unless in dumpOnly mode that will go to local machine.
                print("sleeping because of VirusTotals 4 requests per-minute restriction")
                time.sleep(defaultTimeout)
                count = 0
            # append some data to be pushed to the output file
            tempOutput.append(rows[index][FILENAME])
            tempOutput.append(rows[index][SIZE])
            tempOutput.append(rows[index][CHECKSUM])

            print("\n\n")
            if verbose:
                print("Working on Resource: " + rows[index])
            else:
                print("Working on " + rows[index][FILENAME] + " checksum - " + rows[index][CHECKSUM])

            if dumpOnly == False: # sending everything to VirusTotal Database
                print('sending to VirusTotal')
                # This will check VirusTotal to see if it's been uploaded
                params = {'apikey': APIKey, 'resource': rows[index][CHECKSUM]}
                req = urllib.request.Request(VTRescanURL, urllib.parse.urlencode(params).encode('ascii'))

                # With a proper response
                with urllib.request.urlopen(req) as response: # Start of response from VirusTotal
                    try:
                        # Get the response pushed to JSON
                        json_response = json.loads(response.read())

                        # Check if its nothing
                        if json_response is None:
                            print("response was null continuing")
                            continue
                        # We must have something, check the response code
                        # 0 = VirusTotal hasn't scanned this
                        # 1 = VirusTotal has a ScanID and permalink, get it
                        if json_response['response_code'] == 0:
                            print("file not present in VirusTotal")
                            tempOutput.append("NOT PRESENT")
                        else:
                            print("VirusTotal returned successful ScanID: ")
                            tempOutput.append(json_response['sha256'])
                            tempOutput.append(json_response['permalink'])
                            if verbose:
                                print(json_response)
                            else:
                                print("permalink : " + json_response['permalink'])
                    # Exception information
                    except HTTPError as error:
                        print("HTTPError" + error)
                    except URLError as error:
                        print("URLError" + error)
                    except Exception as ex:
                        # If we get a 204, it means we've re-run too many times and we've cached that 'timeout', need rest for 60 seconds
                        if response.code == 204:
                            print("sleeping because we ran this file(s) VirusTotal scan too quickly")
                            time.sleep(defaultTimeout)
                            continue
            else: #dumpOnly mode
                # sha256
                tempOutput.append("NOSHA")

                # permalink
                tempOutput.append("NOT PRESENT")

            global output
            output.append(tempOutput)

            count += 1
            index += 1

    # Clean the Connection information
    cursor.close()
    conn.close()


def writeDailyScanData():
    totalFiles = len(output)
    newFilesToVirusTotal = 0
    # don't need to add global to output because there is no manipulation of output data
    for line in output:
        for item in line:
            if type(item) != str:
                continue
            if "NOT PRESENT" in item:
                newFilesToVirusTotal += 1
                break
    today = date.today()
    theDate = today.strftime("%d-%m-%Y")
    ID = str(uuid.uuid4()).replace('-', '')

    if dataTableConnection is None:
        connectDataTable()
    dataTableCursor = dataTableConnection.cursor()

    dataTableCursor.execute("INSERT INTO DailyScans VALUES ( ?, ?, ?, ?, ?)", [ID, totalFiles, newFilesToVirusTotal, theDate, time.time()])
    dataTableConnection.commit() # have to call commit in order to write to the database
    dataTableCursor.close()

    # Start of Flare will open window that displays results
    plt.figure(figsize=(9,3))
    plt.bar(["Total Files", "New Files For VirusTotal"], [totalFiles, newFilesToVirusTotal])
    plt.suptitle("Daily Scan - " + theDate)
    plt.show()

def writeWeeklyScanData(): #This shows results of daily scans and scans from 7days.
    if dataTableConnection is None:
        connectDataTable()
    dataTableCursor = dataTableConnection.cursor()

    theEndTime = time.time()
    theStartTime = theEndTime - (7 * 86400) # 7 days times 86400 seconds ( 1 day )

    dataTableCursor.execute("SELECT * FROM DailyScans WHERE Time >= ? AND Time <= ? ", [theStartTime, theEndTime])

    totalFiles = 0
    totalNewFiles = 0
    tDate = []
    tFiles = []
    tNewFiles = []
    for daily in dataTableCursor.fetchall():
        totalFiles += daily[1]
        totalNewFiles += daily[2]
        tFiles.append(daily[1])
        tNewFiles.append(daily[2])
        tDate.append(daily[3])

    print(totalFiles)
    print(totalNewFiles)

    today = date.today()
    theDate = today.strftime("%d-%m-%Y")
    ID = str(uuid.uuid4()).replace('-', '')
    dataTableCursor.execute("INSERT INTO WeeklyScans Values ( ?, ?, ?, ?, ?)", [ID, totalFiles, totalNewFiles, theDate, time.time()])

    dataTableConnection.commit()
    dataTableCursor.close()

    plt.figure(figsize=(9, 3))
    plt.subplot(131)
    plt.bar(["Total Files", "New Files For VirusTotal"], [totalFiles, totalNewFiles])
    plt.subplot(132)
    plt.plot(tDate, tFiles)
    plt.subplot(133)
    plt.plot(tDate, tNewFiles)
    plt.suptitle("Weekly Scan : " + tDate[0] + " - " + str(tDate[-1]))
    plt.show()


def writeFile(fileName):# used in dumpOnly mode this is how it gets into a file
    # Write the file
    with open(fileName, "w") as fileWriter:
        fileWriter.write("File Name\tSize\tChecksum\tSHA256\tPermalink\n")
        for line in output:

            formatted = ''
            cindex = 0
            for item in line:
                if cindex != 0:
                    formatted += ", {}".format(item)
                else:
                    formatted += "{}".format(item)
                cindex += 1

            formatted += '\n'

            fileWriter.write(formatted)
        fileWriter.close()


def main(argv):
    # Make sure were getting all required arguments and any optional ones
    try:
        opts, args = getopt.getopt(argv, "hvk:i:o:s:",
                                   ["apiKey=", "dumpOnly", "timeout=", "ifile=", "ofile=", "dataDbLoc="])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt in ("-i", "--ifile"):
            global driveLocation
            driveLocation = arg
        elif opt in ("-o", "--ofile"):
            global outputFile
            outputFile = arg
        elif opt in ("-k", "--apiKey"):
            global APIKey
            APIKey = arg
        elif opt == "-v":
            global verbose
            verbose = True
        elif opt in ("-d", "--dumpOnly"):
            global dumpOnly
            dumpOnly = True
        elif opt == "--timeout":
            global defaultTimeout
            defaultTimeout = arg
        elif opt == "--dataDbLoc":
            global dataTableLocation
            dataTableLocation = arg
        elif opt in ("-s", "--scanType"):
            global dataTableScanType
            dataTableScanType = arg
        else:
            print("unhandled error")

    if dataTableLocation == '':
        print("--dataDbLoc is REQUIRED")
        usage()
        exit(1)

    print('Input file is : ', driveLocation)
    print('Output file is : ', outputFile)
    print('Data DB Location is : ', dataTableLocation)
    print("APIKey is : ", APIKey)

    foundFiles = glob.glob(driveLocation + "\\**/*.db", recursive=True)

    if foundFiles:
        connectDataTable()

        if dataTableConnection is None:
            print("Error creating / connecting to database, exiting")
            exit(1)
        print(dataTableConnection)
        # Create the cursor
        dataTableCursor = dataTableConnection.cursor()

        # get the count of tables with the name
        dataTableCursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='DailyScans' ''')

        # if the count is 1, then table exists
        if dataTableCursor.fetchone()[0] != 1:
            dataTableCursor.execute(
                '''Create Table DailyScans([generated_id] STRING PRIMARY KEY,[Number_Of_Total_Files] integer, [Number_Of_New_Files] integer, [Date] date, [Time] integer)''')

        dataTableCursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='WeeklyScans' ''')

        # if the count is 1, then table exists
        if dataTableCursor.fetchone()[0] != 1:
            dataTableCursor.execute(
                '''Create Table WeeklyScans([generated_id] STRING PRIMARY KEY,[Number_Of_Total_Files] integer, [Number_Of_New_Files] integer, [Date] date, [Time] integer)''')

        dataTableConnection.commit()
        dataTableCursor.close()

    for file in foundFiles:
        print("Found File -> " + str(file))
        for database in Databases:
            if database in file:
                connect(file, Tables)

    # Always write out a daily scan
    writeDailyScanData()

    if dataTableScanType == "weekly":
        writeWeeklyScanData()

    writeFile(outputFile)
    if dataTableConnection is not None:
        dataTableConnection.close()


if __name__ == "__main__": # Allow to use python code as long as main is defined
    main(sys.argv[1:])
