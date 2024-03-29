#!/usr/bin/python
#
###############################################################################
#  File Integrity Manager                                                     #
# ----------------------------------------------------------------------------#
#  Jason Cherry 2019.                                                         #
# ----------------------------------------------------------------------------#  
# A script to hash a file directory tree.                                     #  
# Software Requirements.
# -----------------------
# - Ability to hash a single file and add to an existing collection of hashes.  
# - There will be two modes, one to generate the hashes, one to verify the 
#   hashes.
# - When a hash is detected to be different the detected hashes will be sent 
#   via an email or other mechanism to raise an alert.
# - The collection of hashes will be written to a file or DB table
# 
###############################################################################
# Change list                                                                 #
# Date       		: Who 	: What                                            #
# -----------------------------------------------------------------------------
# 9th June 2019	    : JC    : Initial version.                                #
# 16th July 2019    : JC    : Add email to, email from and slack webhook URL  #
#                             command line options.                           #
#                             https://api.slack.com/incoming-webhooks         #
#
versionG = "1"
yearG = "16th July 2019"

import stat, os
import sys
import re
#from pathlib import Path
import string
import time
import datetime
import glob
import base64

import requests     # For Slack Notifications.
#import threading	# For threading.
import inspect 		# For debugging line numbers.

#import codecs

#import gzip
#import zipfile
import hashlib 
import smtplib
import ssl

import requests, json

from email.mime.text import MIMEText

thisFileNameG = inspect.getframeinfo(inspect.currentframe()).filename
def lineNum():

    """Returns the current line number in our script. Pay homage to JCherry for this."""
    curFrT = inspect.currentframe()
    thisFileNameT = inspect.getframeinfo(curFrT.f_back).filename
    return str("[" + thisFileNameT + ":" + str(curFrT.f_back.f_lineno) +"] ")

_NoSleep = False # Set to False to allow sleep calls, True stops sleep() function being called.
_DEBUG = False # Set to True to enable debug mode.

printXYMaxStringLengthG = 255
#debugG = False

##
# Global Parameter handling class.
#
# Most are set by the command line options.
#
class GlobalParamsG:

    def __init__(self):
        self.verboseM = 1                   # verbosity or debug output level.
        self.outputDirectoryM = None        # The output path.
        self.noClobberM = False             # Allow file overwrite.
        self.maxDepthSetM = False           # Is the max depth set?
        self.maxDepthM = 0                  # Max directory traversal depth.

        self.logFileM = None                # logfile file handle.
        self.loggingM = 3                   # logging level.

        self.noASCIIEscapeCodesM = True    	# Set to true to use normal or old script output format.
        self.usingStdin = False

        self.generateHashesM = False # Generate the hashes from the file list.
        self.checkHashesM = False
        self.checkFileM = None
        self.monitorModeM = False
        self.monitorModeSleepM = 600

        self.thisHostM = os.uname()[1]

        self.alertConfigM = None



paramsG = GlobalParamsG()



##
# A class to store the loaded profile.
#
class AlertConfig:
    
    def __init__(self):

        self.smtpPortM = 0

        self.smtpPasswordM = None
        self.smtpServerM = None
        self.senderEmailM = ""
        self.receiverEmailM = None

        self.slackWebHookM = None

        self.environmentM = None
        self.projectM = None

    
    def DisplayProfile(self):
            
        printInfo("SMTP Port      : " + str(self.smtpPortM),1)
        printInfo("SMTP Password  : " + str(self.smtpPasswordM),1)
        printInfo("SMTP Server    : " + str(self.smtpServerM),1)
        printInfo("Sender Email   : " + str(self.senderEmailM),1)
        printInfo("Reciever Email : " + str(self.receiverEmailM),1)
        printInfo("",1)
        printInfo("Slack Web Hook : " + str(self.slackWebHookM),1)
        printInfo("",1)
        printInfo("Environment    : " + str(self.environmentM),1)
        printInfo("Project        : " + str(self.projectM),1)


    def __str__(self):

        return str(self.SMTPportM) + " : " + str(self.smtpPasswordM) + " : " + str(self.smtpServerM) + " : " + str(self.senderEmailM) + " : " + str(self.receiverEmailM) + " : " + str(self.slackWebHookM) + " : " + str(self.environmentM) + " : " + str(self.projectM)





def printInfo(stringP, infoLevelP):
    if paramsG.verboseM >= infoLevelP and paramsG.verboseM > 0:
        print(stringP)

    if paramsG.loggingM >= infoLevelP and paramsG.loggingM > 0:
        if paramsG.logFileM != None:
            paramsG.logFileM.write("printInfo(" + str(infoLevelP) + "): " + stringP + "\n")
            paramsG.logFileM.flush()

def printXYDebugNoLock(stringP, debugLevelP, Xp, Yp):
    
    if paramsG.verboseM >= debugLevelP and paramsG.verboseM > 0:
        #printXYClearText("printXYDebug(" + str(debugLevelP) + "): " + stringP, Xp, Yp)
        if len(stringP) < printXYMaxStringLengthG:
            pass
            for x in range(len(stringP), printXYMaxStringLengthG):
                stringP += ' '
        if paramsG.noASCIIEscapeCodesM == False:
            print("\033[" + str(Yp) + ";" + str(Xp) + "f" + "printXYDebug(" + str(debugLevelP) + "): " + stringP[:printXYMaxStringLengthG])
        else:
            print(stringP)

    if paramsG.loggingM >= debugLevelP and paramsG.loggingM > 0:
        if paramsG.logFileM != None:
            paramsG.logFileM.write("printXYDebug(" + str(debugLevelP) + "): " + stringP + '\n')

##
# calling lock more than once will cause a block.
# We need to not call the lock, if we've already called it.
#
def printDebugNoLock(stringP, debugLevelP):
    if paramsG.verboseM >= debugLevelP and paramsG.verboseM > 0:
        print("printDebug(" + str(debugLevelP) + "): " + stringP)

    if paramsG.loggingM >= debugLevelP and paramsG.loggingM > 0:
        if paramsG.logFileM != None:
            paramsG.logFileM.write("printDebug(" + str(debugLevelP) + "): " + stringP + '\n')

##
#
def printHelp():
    print("\n")
    print("-------------------------------------------------------------------------- ")
    print(" -** File Integrity Checker version <" + versionG + ".3> Date:" + yearG + " **-")
    print("-------------------------------------------------------------------------- ")
    print("  FIMChecker.py <options> <target dir name> OR FIMChecker.py <options>     ")
    print("  eg.                                                                      ")
    print("     FIMChecker.py -n -c hashList.txt /git/src                             ")
    
    print(" -**- Commands -**-                                                        ")
    print("   -g : Generate a hash list from the passed path.                         ")
    print("   -c <check file name> : check the hashes of the target files             ")
    print("   -mm <n> : Monitor mode - Don't exit repeatedly check hashes. Sleep for  ")
    print("       n seconds. Or use -monitor                                          ")
    print("   -i <filename and path> : Set the ignore file.                           ")
    
#    print(" -**- Email Options -**-                                                   ")
#    print("   NYI -et <email to address>                                                  ")
#    print("   NYI -ef <email from address>                                                ")
#    print("   NYI -password <email password>                                              ")
#    print("   NYI -smtp <smtp server name> : default [smtp.gmail.com]                     ")
#    print("   NYI -port <smtp server port> : default [465]                                ")
#    #print(" ")
#    print(" -**- Slack Options -**-                                                   ")
#    print("   NYI -slack <slack webhook URL>                                              ")
#
    print(" --** General Options -**-                                                 ")
    print("   -q <n> : Level to output Debug string to std out (1 to 10).             ")
    print("   -l <n> : Level Log debug outtput to file.                               ")
    print("   -o <output directory path> : Output directory to put files out to.      ")
    print("      Try to create the output directory in the current directory.         ")
    print("      Otherwise the directory named will be written to.                    ")
    print("   -m <n> : Set the maximum directory depth to traverse                    ")
    print("   -n : Set no clobber mode, so output files will not be over written.     ")
    print(" -***-                                                                     ")
    print("   -h : print this command line help.                                      ")
    print("--------------------------------------------------------------------------\n\n")

class FileProperties:
    def __init__(self, fileNameP, hashP):
        self.fileNameM = fileNameP
        # md5HashM = 
        self.hashM = hashP

    def __str__(self):
        return self.fileNameM.strip() + " " + self.hashM.strip()

class ErrorMessage:
    valid={"M":"Hash Mismatch","U":"Unknown File","A":"Invalid Audit Value Found"}
    Mismatch = "M"
    Unknown = "U"
    AuditInvalid = "A"

    def __init__(self, valueP):
        if valueP in ErrorMessage.valid.keys():
            self.valueM = str.upper(valueP)
        else:
            self.valueM = "M"

    def __equ__(self, rhsP):
        if self.valueM == rhsP.valueM:
            return True
        else:
            return False

    def __str__(self):
        return ErrorMessage.valid[self.valueM]

class Audit:
    valid={"S":"Scan","I":"Ignore","U":"Unknown"}
    Scan = "S"
    Ignore = "I"
    Unknown = "U"

    def __init__(self, valueP):
        if valueP in str.upper(Audit.valid.keys()):
            self.valueM = str.upper(valueP)
        else:
            self.valueM = "S"

    def __equ__(self, rhsP):
        if self.valueM == rhsP.valueM:
            return True
        else:
            return False

    def __str__(self):
        return self.valueM

class FileDetails:

    def __init__(self, fileNameP, md5HashP, auditValueP = None):
        self.fileNameM = fileNameP
        self.fileNameListM = []
        self.md5HashM = md5HashP
        if auditValueP == None:
            self.auditValueM = Audit.Scan
        else:
            self.auditValueM = auditValueP

        #self.fileObjectM = FileProperties(fileNameP, md5HashP)

        self.addFile(self)


    def addFile(self, fileObjectP):
        #print(lineNum() + "Adding " + fileObjectP.md5HashM + " " + fileObjectP.fileNameM)

        self.fileNameListM.append(fileObjectP)

    def getAuditString(self):
        retValT = self.auditValueM + " " + self.md5HashM + " " + self.fileNameM +"\n"
        return retValT

    def __str__(self):
        fileListT = ''
        retValT = ""
        #print(lineNum())
        for x in self.fileNameListM:
            #if len(self.fileNameListM) > 1:
            fileListT += "\nFileName: " + x.fileNameM.strip() + ', MD5 Hash: ' + x.md5HashM.strip() + ' '
        
        #if len(self.fileNameListM) > 1:    
        #sretValT = "Hash: " + self.md5HashM + "\nFile(s) with a matching hash: " + fileListT
        retValT = fileListT
        #else:
        #    retValT = ""

        return retValT
        # magentoVersionM = magentoVersionP

fileHashesG = {}

##
# Read the hashes from our pre-saved list.
#
def readHashes(pathP):

    try:

        # print(lineNum(), "NOT GETTING HASHES due to TESTING !!!!! ********* "
        # return "00"
        #if _DEBUG == True:
        printDebugNoLock("\033[32;1;1m[+]\033[0m Number of Hashes in our list " + str(len(fileHashesG.keys())),4)

        if len(fileHashesG.keys()) == 0:    # We only want to do this once.
            ##
            # Note: If you need to modify this path.
            #
            if pathP == None:
                pathP = 'md5sums/'
            else:
                printDebugNoLock(lineNum() + " " + pathP,4)

            if pathP == None or pathP == '':
                pathP = "md5sums/"

            printInfo("\033[32;1;1m[+]\033[0m Reading Hashes from "+ pathP + " please wait....", 1)

            breakT = False
            oldNumberOfHashesT = 0
            # If the hash list is a single file...
            if os.path.isdir(pathP) == False and os.path.islink(pathP) == False and os.path.isfile(pathP) == True:
                printDebugNoLock(lineNum() + " Filename passed: " + pathP,4)
                fileHandleT = open(pathP, 'r')
                for lineT in fileHandleT:

                    md5T = ""
                    fileNameT = ""
                    try:
                        auditValueT, md5T, fileNameT = str.split(lineT, ' ',2) # max split is 1, this gets the first string, and treats the rest as the full path, which can include spaces.

                    except Exception as extT:
                        print(lineNum() + lineT)

                        if "too many values to unpack" in str(extT):
                            auditValueT, md5T, tempT, fileNameT = str.split(lineT, ' ')
                            print(lineNum() + str(extT) + " : "+ str(auditValueT) +" :" + str(md5T) + ' : ' + str(tempT) + ' : ' + str(fileNameT))

                    testT = FileDetails(fileNameT, md5T, auditValueT)
                    #print(lineNum() + lineT)
                    if md5T in fileHashesG.keys():

                        numberOfHashesT = len(fileHashesG.keys())
                        if numberOfHashesT != oldNumberOfHashesT:
                            oldNumberOfHashesT = numberOfHashesT
                            printDebugNoLock("\033[32;1;1m[+]\033[0m Number of hashes: " + str(numberOfHashesT), 4)
                        fileHashesG[md5T].addFile(testT)

                        #breakT = True

                        #break
                    
                    else:
                        fileHashesG[md5T] = testT
                        numberOfHashesT = len(fileHashesG.keys())
                        if numberOfHashesT % 500 == 0:
                            printDebugNoLock("\033[32;1;1m[+]\033[0m Number of hashes: " + str(numberOfHashesT),4)
                
            else:
                # Else it is a directory of files. 
                # Todo: Update this code to new format with Audit field.
                for fileT in os.listdir(pathP):
                    #print(lineNum() + str(fileT))

                    fileHandleT = open(pathP + fileT, 'r')
                    for lineT in fileHandleT:

                        md5T = ""
                        fileNameT = ""
                        try:
                            #md5T, fileNameT = str.split(lineT, ' ',1) # max split is 1, this gets the first string, and treats the rest as the full path, which can include spaces.
                            auditValueT, md5T, fileNameT = str.split(lineT, ' ',2)
                        except Exception as extT:
                            print(lineNum() + lineT)

                            if "too many values to unpack" in str(extT):
                                auditValueT, md5T, tempT, fileNameT = str.split(lineT, ' ')
                                printDebugNoLock(lineNum() + str(extT) + " : "+ str(auditValueT) +" :" + str(md5T) + ' : ' + str(tempT) + ' : ' + str(fileNameT,3))

                        testT = FileDetails(fileNameT, md5T, auditValueT)

                        if md5T in fileHashesG.keys():

                            numberOfHashesT = len(fileHashesG.keys())
                            if numberOfHashesT != oldNumberOfHashesT:
                                oldNumberOfHashesT = numberOfHashesT
                            
                            fileHashesG[md5T].addFile(testT)

                            breakT = True

                            break
                        
                        else:
                            fileHashesG[md5T] = testT
                            numberOfHashesT = len(fileHashesG.keys())
                            if numberOfHashesT % 500 == 0:
                                printInfo("\033[32;1;1m[+]\033[0m Number of hashes: " + str(numberOfHashesT),4)
                    
        else:
            printInfo("\033[32;1;1m[+]\033[0m Hash list already initialised.", 5)
    except Exception as extT:
        print(lineNum() + str(extT))


class OutputFileHelper:

    def __init__(self):
        self.fileNamePrefixM = None
        self.outputDirM = None
        self.noClobberValueM = 0
        self.outputHashesFileM = None
        self.alertConfigFileM = None

        self.listOfDefaultPrefixesT = ['hashList','alertconfig']

    def setFileNamePrefix(self, fileNamePrefixP):
        self.fileNamePrefixM = fileNamePrefixP

    def closeFiles(self):

        if self.outputHashesFileM != None:
            self.outputHashesFileM.close()

        if self.alertConfigFileM != None:
            self.alertConfigFileM.close()

    def determineFilenamePrefix(self):

        fileNamePrefixT = ''

        if paramsG.verboseM > 3:
            printDebugNoLock(lineNum() + str(self.fileNamePrefixM), 1)

        if self.fileNamePrefixM != None:
            fileNamePrefixT = '_' + self.fileNamePrefixM # + '.txt'
        else:    
            fileNamePrefixT = ''
        
        self.fileNamePrefixM = fileNamePrefixT


    def determineOutputDirectory(self):
        
        outputDirT = "" #." 
        if paramsG.outputDirectoryM != None:
            outputDirT = os.path.join(outputDirT, paramsG.outputDirectoryM)
            printDebugNoLock(lineNum() + outputDirT + paramsG.outputDirectoryM,10)
        else:
            outputDirT = os.path.join(outputDirT, ".")
            printDebugNoLock(lineNum() + outputDirT, 10)

        self.outputDirM = outputDirT

    ##
    # FilenamePrefix must be obtained before this is run.
    #
    def determineNoClobberValue(self):

        # Figure out the noclobber value.
        noClobberValueT = 0
        if paramsG.noClobberM == True:
            wouldClobberT = False
            for y in xrange(0, 65535):
                wouldClobberT = False
                for x in xrange(0,len(self.listOfDefaultPrefixesT)):
                    
                    if noClobberValueT == 0:
                        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[x] + self.fileNamePrefixM + '.txt')
                        printDebugNoLock(lineNum() + " " + str(testT),5) 
                    else:
                        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[x] + self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.txt') # .padding('0',4) + '.txt')
                        printDebugNoLock(lineNum() + " " + str(testT),5)

                    if os.path.exists(testT):
                        #print(lineNum(), testT
                        wouldClobberT = True
                        noClobberValueT += 1
                        break
                if wouldClobberT == False:
                    # We've got our value.
                    printDebugNoLock(lineNum() + "No Clobber value is: " + str(noClobberValueT), 5)
                    break

                self.noClobberValueM = noClobberValueT
  

    def openOutputHashesFile(self):

        testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[0] + self.fileNamePrefixM + '.txt')
        if self.noClobberValueM != 0:
            testT = os.path.join(self.outputDirM, self.listOfDefaultPrefixesT[0] + self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.txt') #.pad('0',4) + '.txt')

        printDebugNoLock(lineNum() + "Opening File: " + testT , 4)

        self.outputHashesFileM = open(testT, 'w')


    def openAlertConfigFile(self):

        #print lineNum(), os.path.realpath(__file__)
        if len(os.path.dirname(os.path.realpath(__file__))) == 0: 
            testT = os.path.expanduser(os.path.join('~/' + self.listOfDefaultPrefixesT[1] + '.cfg'))
        else:
            testT = os.path.join(os.path.dirname(os.path.realpath(__file__)) + '/' + self.listOfDefaultPrefixesT[1] + '.cfg')
        
        printDebugNoLock(lineNum() + "Opening File: " + testT , 2)

        try:

            self.alertConfigFileM = open(testT, 'r')
        except Exception as extT:
            printInfo(str(extT), 1)

    def loadAlertConfigFile(self):
        #print(lineNum())
        if self.alertConfigFileM != None:
            dataT = self.alertConfigFileM.readlines()

            #print lineNum(), str(dataT)
            currentProfileT = None
            currentProfileT = AlertConfig()
            for x in dataT:
                lineT = str.split(x,'=')

                if len(lineT) >= 1:
                    tagT = str.strip(lineT[0])
                        
                    if '[' in tagT:
                        indexEndT = tagT.find(']')
                        # We've got a name tag.
                        # starting a new profile Object.      
                        continue
                    elif tagT == 'SMTPPort':
                        currentProfileT.smtpPortM = int(lineT[1])
                    elif tagT == 'SMTPPassword':
                        currentProfileT.smtpPasswordM = str.strip(lineT[1])
                    elif tagT == 'SMTPServer':
                        currentProfileT.smtpServerM = str.strip(lineT[1])
                    elif tagT == 'SenderEmail':
                        currentProfileT.senderEmailM = str.strip(lineT[1])
                    elif tagT == 'ReceiverEmail':
                        currentProfileT.receiverEmailM = str.strip(lineT[1])
                    elif tagT == 'SlackWebHook':
                        currentProfileT.slackWebHookM = str.strip(lineT[1])
                    elif tagT == 'Environment':
                        currentProfileT.environmentM = str.strip(lineT[1])
                    elif tagT == 'Project':
                        currentProfileT.projectM = str.strip(lineT[1])


            
            paramsG.alertConfigM = currentProfileT


    def openLogFileOld(self):

        testT = os.path.join(os.getcwd(), time.strftime('%Y%m%d_%H%M%S_') + 'fimlog' + '.log')

        try:
            logFileT = open(testT, 'w')
            paramsG.logFileM = logFileT
            printDebugNoLock(lineNum() + "Logging to file: " + str(testT), 4)
        except IOError as fileOpenException:
            paramsG.logFileM = None
            printDebugNoLock(lineNum(), "I/O error({0}): {1}".format(fileOpenException.errno, fileOpenException.strerror),1)

        return logFileT

    ##
    # Put the log file in the output directory
    # 
    # @todo paramsG.logfileM should locate to this class.
    #
    def openLogFile(self):

        #testT = os.path.join(os.getcwd(), time.strftime('%Y%m%d_%H%M%S_') + 'debugLog' + '.log')
        testT = os.path.join(self.outputDirM, time.strftime('%Y%m%d_%H%M%S_') + 'debugLog' + self.fileNamePrefixM + '.log')

        if self.noClobberValueM != 0:
            testT = os.path.join(self.outputDirM, time.strftime('%Y%m%d_%H%M%S_') + 'debugLog'+ self.fileNamePrefixM + '_' + str(self.noClobberValueM) + '.log') #.pad('0',4) + '.txt')

        printDebugNoLock(lineNum() + "Opening File: " + testT , 4)

        try:
            logFileT = open(testT, 'w')
            paramsG.logFileM = logFileT
            printDebugNoLock(lineNum() + "Logging to file: " + str(testT), 4)
        except IOError as fileOpenException:
            paramsG.logFileM = None
            print(lineNum(), "I/O error({0}): {1}".format(fileOpenException.errno, fileOpenException.strerror))

        return logFileT


outputFilesG = OutputFileHelper()

def checkHashes(listOfFilesP):
    printDebugNoLock(lineNum() + " Entered checkHashes() " + str(len(listOfFilesP)),4)
    readHashes(paramsG.checkFileM)


##
# Generate hashes and write to file.
#
def generateHashes(listOfFilesP):

    outputFilesG.openOutputHashesFile()

    #print "\033[42;1;1m"
    printInfo("\033[32;1;1m[+]\033[0m Generating File Hashes", 1)

    retValT = False

    totalNumberOfFilesT = 0
    #startTimeT = time.time()
    totalNumberofBytesProcessed = 0

    if (listOfFilesP != None):
        totalNumberOfFilesT = len(listOfFilesP)
        printInfo("\033[32;1;1m[+]\033[0m Total Number of files: %d" % totalNumberOfFilesT , 1)
    else:
        printInfo(lineNum() + "\033[31;1;1m[-]\033[0m No input files, must be using stdin.", 1)
        
    linesT = None
    fileNameT = None

    if listOfFilesP == None:
        linesT = sys.stdin
        lineCount = 0
        paramsG.usingStdin = True
        printDebugNoLock(lineNum() + " No input file ", 1)
        #getAndCheckHashFromFile()
    else:

        fileCounterT = 0
        if len(listOfFilesP) > 0:
            printInfo("\033[32;1;1m[+]\033[0m Writing Hashes to output file", 1)
            fileNameT = listOfFilesP.pop()
        else:
            fileNameT = None
        while(fileNameT != None):
            try:
                
                loopCounterT = 0
                outputMessageT = True
                printDebugNoLock(lineNum() + "Hashing File: " + fileNameT, 4)
                hashT = getAndHashFile(fileNameT)

                hashedFileDetailsT = FileDetails(fileNameT, hashT)

                printInfo(hashedFileDetailsT.getAuditString(),4)

                outputFilesG.outputHashesFileM.write(hashedFileDetailsT.getAuditString())

                retValT = True

                printDebugNoLock(lineNum() + "Hashed File: " + str(fileNameT), 4)
            except IOError as err:
                printDebugNoLock(lineNum() + "File " + str(fileNameT) + "IO Error opening file!!!", 4)
                continue
            except OSError as err:
                printDebugNoLock(lineNum() + "Couldn\'t open the file: " + str(fileNameT), 1)
                if err.errno == errno.EAGAIN or err.errno == errno.EWOULDBLOCK:
                    openFileT = None
                continue
            except IOError:
                printDebugNoLock(lineNum() + "Couldn\'t open the file: " + str(fileNameT), 1)
                continue

            finally:
                
                fileCounterT +=1

                printInfo("\033[32;1;1m[+]\033[0m Processing file: %s" % fileNameT, 5)
                
                if len(listOfFilesP) > 0:
                    fileNameT = listOfFilesP.pop()    
                else:
                    fileNameT = None

        loopCounterT = 0
        outputMessageT = True


##
# Get the hash of a file.
#
# opens the file and gets the hash.
#
# Called by: generateHashes().
#
def getAndHashFile(fileNameP):
    try:

        #readHashes('')
        pass 
    except Exception as e:
        print(lineNum() + " Error: " + str(e) + "\n\n")


    returnHashT = ''
    fileDataT = None
    fhand = None
    newResponseT = None

    linesP = ""

    try:

        printDebugNoLock(lineNum() + " file:" + fileNameP, 4)

        if os.path.isfile(fileNameP) == True:
            openFileT = open(fileNameP,  'rb')
            if openFileT != None:

                linesP = openFileT.read() # Upto a million lines!

                if linesP != None:
                    #linesP += fileNameP # add the filename so we can pick up if files get moved.
                    returnHashT = hashlib.md5(linesP).hexdigest()
                else:
                    print(lineNum(), fileNameP, " is None!")

            openFileT.close()

        else:
            printDebugNoLock(lineNum() + str(fileNameP) + " is not a file!",4)
    except exT as Exception:
        print(lineNum() + str(exT))

    return returnHashT

##
# Send message to slack
#
def send_slack_alert(dataP, context=None):
    
    webhook_urlT = paramsG.alertConfigM.slackWebHookM
    printInfo(webhook_urlT,2)

    thisHostT = paramsG.thisHostM      

    printInfo("\033[31;1;1m[-]\033[0m Sending Slack Message...",1)

    slack_dataT = {'text': "Possible File Integrity Compromise Detected on host: " + str(thisHostT), \
        "attachments":  [ \
                         { \
                         "fallback": "", \
                         "color": "#78281F",\
                         "pretext": "",\
                         "author_name": "Data Source: File Integrity Manager",\
                         "author_link": "",\
                         "author_icon": "",\
                         "title": "",\
                         "title_link": "",\
                         "text": "",\
                         "fields": [\
                                    {\
                                    "title": "host",\
                                    "value": str(dataP['host']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "environment",\
                                    "value": str(dataP['environment']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "project",\
                                    "value": str(dataP['project']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "message",\
                                    "value": str(dataP['message']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "file properties",\
                                    "value": str(dataP['fileproperties']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "detected file",\
                                    "value": str(dataP['checkedfile']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "error message",\
                                    "value": str(dataP['error']),\
                                    "short": "false"\
                                    }\
                                    ],\
                         "ts":  str(time.time())\
                         }\
                         ]\
        }


    responseT = requests.post(
                             webhook_urlT, data=json.dumps(slack_dataT),
                             headers={'Content-Type': 'application/json'}
                             )

    if responseT.status_code != 200:
        raise ValueError(
                         'Request to slack returned an error %s, the response is:\n%s'
                         % (responseT.status_code, responseT.text)
                         )

##
# Send message to slack
#
def send_slack_notification(dataP, context=None):
    
    webhook_urlT = paramsG.alertConfigM.slackWebHookM
    printInfo(webhook_urlT,2)

    thisHostT = paramsG.thisHostM      

    printInfo("\033[32;1;1m[+]\033[0m Sending Slack Started Notification...",1)

    slack_dataT = {'text': "File Integrity Monitor is running: " + str(thisHostT), \
        "attachments":  [ \
                         { \
                         "fallback": "", \
                         "color": "#78281F",\
                         "pretext": "",\
                         "author_name": "Data Source: File Integrity Manager",\
                         "author_link": "",\
                         "author_icon": "",\
                         "title": "",\
                         "title_link": "",\
                         "text": "",\
                         "fields": [\
                                    {\
                                    "title": "host",\
                                    "value": str(dataP['host']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "environment",\
                                    "value": str(dataP['environment']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "project",\
                                    "value": str(dataP['project']),\
                                    "short": "false"\
                                    },\
                                    {\
                                    "title": "message",\
                                    "value": str(dataP['message']),\
                                    "short": "false"\
                                    } \
                                    ],\
                         "ts":  str(time.time())\
                         }\
                         ]\
        }


    responseT = requests.post(
                             webhook_urlT, data=json.dumps(slack_dataT),
                             headers={'Content-Type': 'application/json'}
                             )

    if responseT.status_code != 200:
        raise ValueError(
                         'Request to slack returned an error %s, the response is:\n%s'
                         % (responseT.status_code, responseT.text)
                         )


##
# Pass the full hash
#
def getFileNameRecord(fileNameP):
    retValT = None
    printDebugNoLock(lineNum() + fileNameP, 4)
    for x in fileHashesG.keys():
        printDebugNoLock(lineNum() + x, 4)
        printDebugNoLock(lineNum() + fileHashesG[x].fileNameM, 4)
        if fileNameP == str.strip(fileHashesG[x].fileNameM):
            printDebugNoLock(lineNum() + fileHashesG[x].fileNameM, 4)
            retValT = fileHashesG[x]
            break

    return retValT

def raiseAlert(filePropertiesP, errorMessageP, checkedFileP = None):
    
    portT = paramsG.alertConfigM.smtpPortM # for SSL
    emailPasswordT = paramsG.alertConfigM.smtpPasswordM

    context = ssl.create_default_context()
    
    smtp_server=paramsG.alertConfigM.smtpServerM
    
    sender_email=paramsG.alertConfigM.senderEmailM
    receiver_email=paramsG.alertConfigM.receiverEmailM
    
    thisHostT = paramsG.thisHostM

    dataT = {"host":"","environment":"","project":"","message":"",'fileproperties':'','checkedfile':"",'error':""}

    printDebugNoLock(lineNum() + str(thisHostT),4)

    dataT['host'] = thisHostT
    dataT['environment'] = paramsG.alertConfigM.environmentM
    dataT['project'] = paramsG.alertConfigM.projectM

    server = smtplib.SMTP_SSL(smtp_server,portT)

    try:
        if paramsG.alertConfigM.senderEmailM != None:
            server.login(sender_email, emailPasswordT)

            message = " Subject: Possible File Integrity Compromise Detected on " + str(thisHostT) + \
            "\n\n\n"

            message += "\nHost: " + str(thisHostT) +"\n" 
            message += "\nEnvironment: " + str(paramsG.alertConfigM.environmentM) + "\n"
            message += "\nProject: " + str(paramsG.alertConfigM.projectM) + "\n"
            

            if filePropertiesP != None:
                
                message += "\nFile Integrity has been compromised.\n" + \
                "\nModified File Details: " + str(filePropertiesP) + "\n"
                dataT['fileproperties'] = str(filePropertiesP)

            if checkedFileP != None:
                message +=  "\nDetected File Details: " + str(checkedFileP) + "\n"
                dataT['checkedfile'] = str(checkedFileP)

            message += "\nError Message: " + str(errorMessageP) + "\n\n"        
            dataT['message'] = message

            dataT['error'] = str(errorMessageP)

            printInfo("\033[31;1;1m[-]\033[0m Sending Email...",1)
            server.sendmail(sender_email, receiver_email, message)

        if paramsG.alertConfigM.slackWebHookM != None:
            
            send_slack_alert(dataT)

        # TODO: Send email here
    except Exception as e:
        
        print(e)
    finally:
        server.quit() 


def startedNotification():
    
    portT = paramsG.alertConfigM.smtpPortM # for SSL
    emailPasswordT = paramsG.alertConfigM.smtpPasswordM

    context = ssl.create_default_context()
    
    smtp_server=paramsG.alertConfigM.smtpServerM
    
    sender_email=paramsG.alertConfigM.senderEmailM
    receiver_email=paramsG.alertConfigM.receiverEmailM
    
    thisHostT = paramsG.thisHostM

    dataT = {"host":"","environment":"","project":"","message":""}

    printDebugNoLock(lineNum() + str(thisHostT),4)

    dataT['host'] = thisHostT
    dataT['environment'] = paramsG.alertConfigM.environmentM
    dataT['project'] = paramsG.alertConfigM.projectM

    server = smtplib.SMTP_SSL(smtp_server,portT)

    try:
        if paramsG.alertConfigM.senderEmailM != None:
            server.login(sender_email, emailPasswordT)

            message = " Subject: File Integrity Monitor started on " + str(thisHostT) + \
            "\n\n\n"

            #dataT['message'] = message

            #if filePropertiesP != None:
            message += "\nHost: " + str(thisHostT) +"\n"
            message += "\nEnvironment: " + str(paramsG.alertConfigM.environmentM) + "\n"
            message += "\nProject: " + str(paramsG.alertConfigM.projectM) + "\n"
            message += "\nFile Integrity monitor has been started with a " + str(paramsG.monitorModeSleepM) + " second polling period.\n" 

                #"\nModified File Details: " + str(filePropertiesP) + "\n"
                #dataT['fileproperties'] = str(filePropertiesP)

            # if checkedFileP != None:
            #     message +=  "\nDetected File Details: " + str(checkedFileP) + "\n"
            #     dataT['checkedfile'] = str(checkedFileP)

            #message += "\nError Message: " + str(errorMessageP) + "\n\n"        

            #dataT['error'] = str(errorMessageP)
            dataT['message'] = message

            #printInfo("\033[32;1;1m[+]\033[0m 
            printInfo("\033[32;1;1m[+]\033[0m Sending Email Started Notification...",1)
            server.sendmail(sender_email, receiver_email, message)

    except Exception as e:
        printDebugNoLock(lineNum() + str(e), 2)
    finally:
        try:
            server.quit() 
        except Exception as e2:
            printInfo("\033[31;1;1m[-]\033[0m Problem Connecting to email server: " + str(smtp_server) + ".",1)
            printInfo("\033[31;1;1m[-]\033[0m Error: " + str(e2),1)

    try:
        #if paramsG.alertConfigM.slackWebHookM != None:
            
         send_slack_notification(dataT)

        # TODO: Send email here
    except Exception as e:
        printDebugNoLock(lineNum() + str(e), 2)
    finally:
        try:
            #server.quit()
            pass
        except Exception as e2:
            printInfo("\033[31;1;1m[-]\033[0m Problem Connecting to email server: " + str(smtp_server) + ".",1)
            printInfo("\033[31;1;1m[-]\033[0m Error: " + str(e2),1)



##
# Check if a hash matches a file in our hashlist.
#
def getAndCheckHashFromFile(fileNameP):
    try:

        readHashes('')

    except Exception as e:
        print(lineNum() + " Error: " + str(e) + "\n\n")

    returnHashT = ''
    fileDataT = None
    fhand = None
    newResponseT = None

    linesP = ""

    if os.path.isfile(fileNameP) == True:
        openFileT = open(fileNameP,  'rb')
        if openFileT != None:
            linesP = openFileT.read() # Upto a million lines!

            if linesP != None:
                returnHashT = hashlib.md5(linesP).hexdigest()
        
                checkedFileT = FileDetails(fileNameP, returnHashT, Audit.Unknown)
                if returnHashT in fileHashesG.keys():
                    pass
                else:
                    printInfo("\033[32;1;1m[+]\033[0m Filename: " + fileNameP, 1)
                    printInfo("\033[31;1;1m[-]\033[0m Did Not find hash: " + returnHashT + " in hash list.", 1)
                    fileRecordT = getFileNameRecord(fileNameP)
                    if fileRecordT != None:
                        printInfo("\033[32;1;1m[+]\033[0m Recorded Hash: " + fileRecordT.md5HashM,1)
                        printInfo("\033[32;1;1m[+]\033[0m Audit Status: " + str(fileRecordT.auditValueM), 1)
                        if fileRecordT.auditValueM == Audit.Ignore:
                            printInfo("\033[32;1;1m[+]\033[0m File can be ignored!", 1)
                        elif fileRecordT.auditValueM == Audit.Scan:
                            printInfo("\033[31;1;1m[-]\033[0m File must be checked!", 1)
                            # Raise Alert!
                            raiseAlert(fileRecordT, ErrorMessage('M'), checkedFileT)
                        else:
                            printInfo("\033[31;1;1m[-]\033[0m Invalid Audit Value!", 1)
                            raiseAlert(fileRecordT, ErrorMessage('A'))    
                        
                    else:
                        # File not in hash list.
                        # Raise Alert!
                        printInfo("\033[31;1;1m[-]\033[0m Filename: " + str(fileNameP) + " is not in hashlist!!!", 1)
                        ignoreThisFileT = ignoreFileG.checkIgnore(fileNameP)
                        if ignoreThisFileT == False:
                            raiseAlert(fileRecordT, ErrorMessage('U'), checkedFileT)
            else:
                printDebugNoLock(lineNum(), fileNameP, " is None!",1)


    else:
        printDebugNoLock(lineNum() + fileNameP + " is not a file!",6)

##
# A class to process the ignore file.
# This is the .gitignore file.
#
class IgnoreFile:
    
    ##
    # The list of ignore paths and files.


    def __init__(self, ignoreFileNameP):
        
        self.ignoreFileM = ignoreFileNameP
        self.ignorePathListM = []
        self.ignoreExtensionsListM = []
        self.ignoreFileListM = []

        self.ignoredFilesM = []

        self.process()

    def setRootPath(self, rootPathP):
        printInfo(lineNum() + "\033[32;1;1m[+]\033[0m Reading Path to Ignore...",2)
        
        tempIgnorePathListT = []
        if rootPathP.endswith('/'):
            print lineNum(), rootPathP
            rootPathP = rootPathP[0:len(rootPathP)-1]
            print lineNum(), rootPathP

        for x in self.ignorePathListM:
            #newPathT = os.path.join(rootPathP, x)
            newPathT = rootPathP + x
            tempIgnorePathListT.append(newPathT)
            printDebugNoLock(lineNum() + newPathT, 3)

        self.ignorePathListM = tempIgnorePathListT
        printInfo(lineNum() + "\033[32;1;1m[+]\033[0m Reading the Files to Ignore...",2)
        tempIgnoreFileListT = []
        for x in self.ignoreFileListM:
            if x[0] == '/':
                newFilePathT = rootPathP + x
            else:
                newFilePathT = x

            tempIgnoreFileListT.append(newFilePathT)
            printDebugNoLock(lineNum() + newFilePathT, 3)
        self.ignoreFileListM = tempIgnoreFileListT
        
    ##
    # @todo: Add this to the getDirectoryFiles() function instead of the insitu code.
    #
    def checkIgnore(self, fileNameP):
        
        foundIgnoreT = False
        for extensionT in self.ignoreExtensionsListM:
            if fileNameP.endswith(extensionT):
                printDebugNoLock(lineNum() + "Found extension in ignore list ! Filename: " + fileNameP + " ends in " + str(extensionT) + ", Ignoring!!!", 2) # I'm not sure why we care.
                foundIgnoreT = True
                break
        if foundIgnoreT == False:
            for ignoreT in self.ignoreFileListM:
                printDebugNoLock(lineNum() + ignoreT + " : " +  fileNameP,4)
                ignoreIndexT = string.find(fileNameP, ignoreT)

                if ignoreIndexT >= 0 and ignoreIndexT <= 3: # skip . chars.
                    printDebugNoLock(lineNum() + "Found filename in ignore list ! Ignoring... " + str(ignoreT) + " : " + str(fileNameP),2)
                    foundIgnoreT = True
                    break
        
        if foundIgnoreT == False:
            for ignoreT in ignoreFileG.ignorePathListM:
                printDebugNoLock(lineNum() + ignoreT + " : " + fileNameP, 4)
                rootTempT = ''
                if fileNameP.endswith('/'):
                    rootTempT = fileNameP
                else:
                    rootTempT = fileNameP + '/'

                ignoreIndexT = string.find(fileNameP, ignoreT)
                if ignoreIndexT >= 0 and ignoreIndexT <= 3: # skip . chars.
                    printDebugNoLock(lineNum() + "Found path in ignore list ! Ignoring..." + str(ignoreT)  + " : " + fileNameP,2)
                    foundIgnoreT = True
                    break

        return foundIgnoreT
        

    def process(self):

        returnHashT = ''
        fileDataT = None
        fhand = None
        newResponseT = None

        linesT = ""

        try:

            printDebugNoLock(lineNum() + " file:" + self.ignoreFileM, 4)

            if os.path.isfile(self.ignoreFileM) == True:
                openFileT = open(self.ignoreFileM,  'r')
                if openFileT != None:
                    linesT = openFileT.readlines() # Upto a million lines!
                    if linesT != None:
                        #linesP += fileNameP # add the filename so we can pick up if files get moved.
                        for lineT in linesT:
                            currentT = string.strip(str(lineT))
                            if lineT[0] == "!" or lineT[0] =='#' or len(str.strip(lineT)) == 0:
                                printDebugNoLock(lineNum() + "starts with " + str(lineT[0]) , 4)
                                printInfo("Line Ignored: " + str(lineT),4)
                            elif lineT[0] == "*" and len(lineT) > 1:
                                # This will be a blanket extension ignore.
                                tempT = string.split(lineT,".")
                                extensionT = string.strip(str(tempT[len(tempT) -  1]))
                                self.ignoreExtensionsListM.append(extensionT)
                                printInfo("Extension added to ignore list: " + extensionT, 2)
                                printDebugNoLock(lineNum() + str(string.split(lineT, ".")),4)
                            elif len(lineT) > 0 and currentT[len(currentT) - 1] == '*':
                                directoryT = string.split(lineT,"*")[0]
                                self.ignorePathListM.append(directoryT)
                                printInfo("Directory added to ignore list: " + str(directoryT), 2)
                            elif currentT[len(currentT)-1] == '/':
                                self.ignorePathListM.append(currentT)
                                printInfo("Directory added to ignore list: " + str(currentT), 2)
                            else:  
                                if os.path.isdir(currentT):
                                    printInfo(lineNum() + "Directory: " + currentT,4)
                                    self.ignorePathListM.append(currentT)
                                    printInfo("Directory added to ignore list: " + str(currentT), 2)
                                elif os.path.isfile(currentT):
                                    printInfo(lineNum() + "File: " + currentT, 4)
                                    printInfo("File added to ignore list: " + str(currentT), 2)
                                    self.ignoreFileListM.append(currentT)
                                else:
                                    # we assume it's a file.
                                    printInfo(lineNum() + "Unknown File: " + currentT, 4)
                                    printInfo("File added to ignore list: " + str(currentT), 2)
                                    self.ignoreFileListM.append(currentT)


                            printDebugNoLock(lineNum() + str(lineT),4)

                    else:
                        printDebugNoLock(lineNum() + " Ignore file not set!", 1)

                openFileT.close()

            else:
                printDebugNoLock(lineNum() + str(self.ignoreFileM) + " is not a file!",1)

        except Exception as exT:
            print(lineNum() + str(exT))

    def outputLists(self):
        printInfo("\033[32;1;1m[+]\033[0m Ignoring Paths...",1)
        for x in self.ignorePathListM:
            printInfo(x,1)
        printInfo("\033[32;1;1m[+]\033[0m Ignoring Extensisons",1)
        for x in self.ignoreExtensionsListM:
            printInfo(x,1)
        printInfo("\033[32;1;1m[+]\033[0m Ignoring Files...",1)
        for x in self.ignoreFileListM:
            printInfo(x,1)

    def printIgnored(self):
        printInfo("\033[32;1;1m[+]\033[0m Ignored file list...",2)
        for x in self.ignoredFilesM:
            printInfo(x,2)

ignoreFileG = None


##
# Get the list files matching the extension (extensionP) 
# contained in the passed directory dirP.
# Returns the full path file names as a list.
#def getAllFilesInDirectory(dirP, extensionP, maxDepthP):
# We now check the ignore list.
#
def getAllFilesInDirectory(dirP, maxDepthP):

    returnFileListT = []
    
    printDebugNoLock(lineNum() + "MaxDepth on entry is " + str(maxDepthP), 4)
    if maxDepthP > 0 or paramsG.maxDepthSetM == False:
        if paramsG.maxDepthSetM == True:
            maxDepthP -= 1 # Track our way to the maximum depth level.
        else:
            maxDepthP += 1 # Track the number of levels we traverse.

        if paramsG.verboseM > 3:
            print(">")
        printInfo(lineNum() + "Get all files in: " + dirP, 4)
        dailyDirsStructT = os.walk(dirP, followlinks=False)
        dailyDirsT = [] # The directory names returned from os.walk
        rootT = ''
        for rootT, dailyDirsT, filesT in dailyDirsStructT:
            foundIgnoreT = False
            if os.path.islink(rootT):
                printDebugNoLock("%s%s %s : %s" % (lineNum(), "Link file hit!: ", rootT, os.path.isfile(rootT)), 1)
                continue

            foundIgnoreT = ignoreFileG.checkIgnore(rootT)

            if len(filesT) == 1:
                printDebugNoLock(lineNum() + os.path.join(rootT), 4)
                globFilesT = glob.glob(rootT)
                printDebugNoLock(lineNum() + "Files: " + os.path.join(rootT, filesT[0]), 3)
                if len(globFilesT) == 1:
                    printDebugNoLock(lineNum() + "Globs: " + os.path.join(rootT, globFilesT[0]), 3)

                    if foundIgnoreT == False:
                        foundIgnoreT = ignoreFileG.checkIgnore(os.path.join(rootT, globFilesT[0]))

                if foundIgnoreT == False:
                    foundIgnoreT = ignoreFileG.checkIgnore(os.path.join(rootT, filesT[0]))

                if foundIgnoreT == False:
                    returnFileListT.append(os.path.join(rootT, filesT[0]))

            elif len(filesT) > 1:
                printDebugNoLock(lineNum() + "Files is > 1", 4)

                for fileT in filesT:
                    foundIgnoreT = False
                    if os.path.exists(os.path.join(rootT,fileT)):
                        isFifoT = stat.S_ISFIFO(os.stat(os.path.join(rootT,fileT)).st_mode)
                        if isFifoT:
                            printDebugNoLock("%s%s %s : %s : %s" % (lineNum(), "Fifo file hit!: ", os.path.join(rootT,fileT), os.path.isfile(rootT), str(isFifoT)), 1)
                            continue
                        isFifoT = stat.S_ISCHR(os.stat(os.path.join(rootT,fileT)).st_mode)
                        if isFifoT:
                            printDebugNoLock("%s%s %s : %s : %s" % (lineNum(), "Character special file hit!: ", os.path.join(rootT,fileT), os.path.isfile(rootT), str(isFifoT)), 1)
                            continue
                        isFifoT = stat.S_ISBLK(os.stat(os.path.join(rootT,fileT)).st_mode)
                        if isFifoT:
                            printDebugNoLock("%s%s %s : %s : %s" % (lineNum(), "Block special file hit!: ", os.path.join(rootT,fileT), os.path.isfile(rootT), str(isFifoT)),1)

                        isFifoT = stat.S_ISSOCK(os.stat(os.path.join(rootT,fileT)).st_mode)
                        if isFifoT:
                            printDebugNoLock("%s%s %s : %s : %s" % (lineNum(), "Sock file hit!: ", os.path.join(rootT,fileT), os.path.isfile(rootT), str(isFifoT)),1)

                        isFifoT = stat.S_ISREG(os.stat(os.path.join(rootT,fileT)).st_mode)
                        if isFifoT == 0:
                             printDebugNoLock("%s%s %s : %s : %s" % (lineNum(), "Sock file hit!: ", os.path.join(rootT,fileT), os.path.isfile(rootT), str(isFifoT)),1)

                    if foundIgnoreT == False:
                        foundIgnoreT = ignoreFileG.checkIgnore(os.path.join(rootT, fileT))

                    if foundIgnoreT == False:
                        returnFileListT.append(os.path.join(rootT, fileT))

            printDebugNoLock(lineNum() + str(dailyDirsT), 5)

            if len(dailyDirsT) > 0:
                for subDirsT in dailyDirsT:
                    printDebugNoLock(lineNum() + str(subDirsT) + " : " + str(len(dailyDirsT)) + " : " + str(len(subDirsT)) + " : " + str(os.path.isdir(subDirsT)), 7)
                    if len(subDirsT) == 0: # An issue was reported where the code would repeately recurse, then python would barf.
                        pass                   # So I've done this check, as when I examined the values the subDirsT was a zero length string.
                        break
                    dontCareT = None
                    tempFilesT, dontCareT = getAllFilesInDirectory(os.path.join(rootT,subDirsT), maxDepthP)

                    for tempFileT in tempFilesT:
                        returnFileListT.append(tempFileT)
            break;

        if paramsG.verboseM > 3:
            print("<")
    else:
        printDebugNoLock(lineNum() + "Maxium depth of " + str(paramsG.maxDepthM) + " was reached!",1)
        printDebugNoLock(lineNum() + "Did not process: ", dirP,1)

    

    return returnFileListT, dirP # return the top level directory

##
# Todo: Modify to account for Audity property and raise alert.
#
def auditFileHashes(listOfFilesP):

    global startTimeT

    retValT = False

    totalNumberOfFilesT = 0
    startTimeT = time.time()
    totalNumberofBytesProcessed = 0

    #printInfo("[+] Checking Hashes... ", 1)

    if (listOfFilesP != None):
        totalNumberOfFilesT = len(listOfFilesP)
        printInfo("\033[32;1;1m[+]\033[0m Total Number of files: %d" % totalNumberOfFilesT , 1)
    else:
        printInfoNoLock("No input files, must be using stdin.",4)

    linesT = None
    fileNameT = None

    if listOfFilesP == None:
        linesT = sys.stdin
        lineCount = 0
        paramsG.usingStdin = True
        printInfo("\033[31;1;1m[-]\033[0m Error: No input file ", 1)
    else:

        fileCounterT = 0
        if len(listOfFilesP) > 0:
            fileNameT = listOfFilesP.pop()
        else:
            fileNameT = None
        while(fileNameT != None):  
            try:
                
                loopCounterT = 0
                outputMessageT = True

                getAndCheckHashFromFile(fileNameT)
                retValT = True
                printDebugNoLock(lineNum() + "Hashed File: " + fileNameT, 4)
            except IOError as err:
                printDebugNoLock(lineNum() + "File " + str(fileNameT) + "IO Error opening file!!!", 1)
                continue
            except OSError as err:
                printDebugNoLock(lineNum() + "Couldn\'t open the file: " + str(fileNameT), 1)
                if err.errno == errno.EAGAIN or err.errno == errno.EWOULDBLOCK:
                    openFileT = None
                continue
            except IOError:
                printDebugNoLock(lineNum() + "Couldn\'t open the file: " + str(fileNameT), 1)
                continue

            finally:
                
                fileCounterT +=1

                printInfo("\033[32;1;1m[+]\033[0m Processing file: %s" % fileNameT, 11)
                
                if len(listOfFilesP) > 0:
                    fileNameT = listOfFilesP.pop()    
                else:
                    fileNameT = None

        loopCounterT = 0
        outputMessageT = True

    return retValT    


##
# processCommandLine()
#	
def processCommandLine(fileNameP):

    global ignoreFileG

    listOfFilesT = None
    currentParamT = 1
    fileNameT = None
    paramsG.unicodeM = False
    skipT = 0
    topLevelDirT = None
    for argT in sys.argv[1:]:
        if skipT > 0:
            skipT = 0
            currentParamT += 1
            printDebugNoLock(lineNum() + "Skipping Paremeter: " + str(argT), 4)
            continue
        if os.path.isdir(argT) == True:
            printDebugNoLock(lineNum() + str(argT), 6)
            printDebugNoLock(lineNum() + "Maxdepth set to: " + str(paramsG.maxDepthM), 6)

            if ignoreFileG == None:
                ignoreFileG = IgnoreFile("")
            ignoreFileG.setRootPath(argT) # This means the ignore file must always be set at command line.
            printInfo("%s" % ("\033[32;1;1m[+]\033[0m Building Directory List. Please wait..."),1)
            #print lineNum(), argT
            
            listOfFilesT, topLevelDirT = getAllFilesInDirectory(argT, paramsG.maxDepthM)
            ignoreFileG.printIgnored()
            fileReadT = sys.argv[currentParamT]

            if fileNameT == None:                
                for x in xrange(0,10):
                    if fileNameT != None and x < len(fileNameT):
                        fileNameT = string.split(fileReadT, ".")[x]
                    if fileNameT != None and len(fileNameT) > 0:
                        printDebugNoLock(lineNum() + "Directory name set to: " + str(fileNameT), 4)
                        break
                printDebugNoLock(lineNum() + str(fileNameT), 5)

            if (fileNameT != None): 
                fileNameP = fileNameT
                fileNameP = string.replace(fileNameP,'/','')
                fileNameP = string.replace(fileNameP,'\\','')
                fileNameT = fileNameP
            
            currentParamT += 1
            continue

        elif argT == '-i':
            if len(sys.argv[1:]) > currentParamT:
                #
                printInfo("\033[32;1;1m[+]\033[0m Ignore filename set to: " + str(sys.argv[currentParamT + 1]),1)
                ignoreFileNameT = sys.argv[currentParamT + 1]

                ignoreFileG = IgnoreFile(ignoreFileNameT)

                ignoreFileG.outputLists()

                currentParamT += 1
                skipT = 1
                continue
            else:
                currentParamT += 1
                continue
        elif argT == '-o':
            if len(sys.argv[1:]) > currentParamT:
                printDebugNoLock(lineNum() + str(sys.argv[1:]) + " : " + str(currentParamT) + " : " + str(argT) + " : " + str(len(sys.argv[1:])), 6)
                printDebugNoLock(lineNum() + str(sys.argv[currentParamT + 1]) ,2)
                paramsG.outputDirectoryM = str(sys.argv[currentParamT + 1])
                printInfo("\033[32;1;1m[+]\033[0m Output directory set to: " + str(paramsG.outputDirectoryM) , 1)

                currentParamT += 1

                skipT = 1
                if not os.path.exists(paramsG.outputDirectoryM):
                    os.makedirs(paramsG.outputDirectoryM)
                else:
                    if paramsG.verboseM >= 1:
                        printInfo("Output Directory \'%s\'%s" % (str(paramsG.outputDirectoryM), " already exists!"),3)
                continue
            else:
                currentParamT += 1
                continue
        elif argT == '-n': # Noclobber
            printInfo("\033[32;1;1m[+]\033[0m Noclobber set on.", 4)
            currentParamT += 1
            paramsG.noClobberM = True
            continue
        elif argT == '-m': # For maxdepth and level
            paramsG.maxDepthM = 0
            if len(sys.argv[1:]) > currentParamT:
                try:
                    paramsG.maxDepthM = int(sys.argv[currentParamT+1])
                    printDebugNoLock(lineNum() + "MaxDepth set to: " + str(paramsG.maxDepthM), 1)
                    if paramsG.maxDepthM == 0:
                        paramsG.maxDepthSetM = False
                    else:
                        paramsG.maxDepthSetM = True    
                    
                    currentParamT += 1
                    skipT = 1
                    
                except ValueError:
                    currentParamT += 1
                    paramsG.maxDepthSetM = False
                    paramsG.maxDepthM = 0

                printInfo("\033[32;1;1m[+]\033[0m MaxDepth set to: " + str(paramsG.maxDepthM), 1)

                
                continue
            else:
                paramsG.maxDepthSetM = False
                currentParamT += 1
                continue

        elif argT == '-q': # For verbose and level
            # Simply switch on quiet mode.
            # At the moment just set verbose mode to 3.
            # I envisage that we'll have multiple levels of verbosity.
            paramsG.verboseM = 0

            if len(sys.argv[1:]) > currentParamT:
                try:
                    paramsG.verboseM = int(sys.argv[currentParamT + 1])
                    currentParamT += 1
                    skipT = 1
                except ValueError:
                    currentParamT += 1
                    paramsG.verboseM = 0

                printInfo("\033[32;1;1m[+]\033[0m Verbosity set to: " + str(paramsG.verboseM), 4)
                printInfo("\033[32;1;1m[+]\033[0m Commandline: " + str(sys.argv[1:]), 4)                
                continue

            else:
                paramsG.verboseM = 0
                currentParamT += 1
                continue

        elif argT == '-mm': # For verbose and level
            # Simply switch on quiet mode.
            # At the moment just set verbose mode to 3.
            # I envisage that we'll have multiple levels of verbosity.
            paramsG.monitorModeM = True
            paramsG.monitorModeSleepM = 600

            if len(sys.argv[1:]) > currentParamT:
                try:
                    paramsG.monitorModeSleepM = int(sys.argv[currentParamT + 1])
                    currentParamT += 1
                    skipT = 1
                except ValueError:
                    currentParamT += 1
                    paramsG.monitorModeSleepM = 600

                printInfo("\033[32;1;1m[+]\033[0m Monitor Mode Sleep time set to: " + str(paramsG.monitorModeSleepM), 1)
                #printInfo("[+] Commandline: " + str(sys.argv[1:]), 4)                
                continue

            else:
                paramsG.monitorModeSleepM = 600
                paramsG.monitorModeM = False
                currentParamT += 1
                continue
                


                
        elif argT == '-l': # For verbose and level logging

            paramsG.loggingM = 3

            if len(sys.argv[1:]) > currentParamT:
                try:
                    paramsG.loggingM = int(sys.argv[currentParamT+1])
                    currentParamT += 1
                    skipT = 1
                except ValueError:
                    currentParamT += 1
                    paramsG.loggingM = 0

                if paramsG.loggingM > 0:
                    outputFilesG.openLogFileOld()           #### !!!!! Open the log file! only if logging value is set!

                printInfo(lineNum() + "Logging value: " + str(paramsG.loggingM),3)

                continue
            else:
                outputFilesG.openLogFileOld()               #### Open the log file...
                paramsG.loggingM = 3
                currentParamT += 1
                continue

        elif argT == '-d': # For very verbose debug output
            # Simply switch on quiet mode.
            # At the moment just set verbose mode to 3.
            # I envisage that we'll have multiple levels of verbosity.
            paramsG.verboseM = 11
            printInfo(lineNum() + "*** Debug Mode ***", 1)

            printInfo(lineNum() + "Outputting all output to stdout, verbose mode turned up to 11.", 3)
            currentParamT += 1

        elif argT == '-g': # Generate Hashes Mode.
            paramsG.generateHashesM = True
            currentParamT += 1
            continue

        elif argT == '-c': #Check Hashes Mode.
            paramsG.checkHashesM = True
            checkFileNameT = None

            if len(sys.argv[1:]) > currentParamT:
                #
                checkFileT = sys.argv[currentParamT + 1]
                printInfo("\033[32;1;1m[+]\033[0m Hash check filename set to: " + checkFileT, 4)
                paramsG.checkFileM = checkFileT
                
                splitFileNameT = string.split(checkFileT, ".")
                tempT = None
                temp2T = None
                #This loop will append everything except the last field... ie the extention.
                # could've done for x in xrange(0,len(splitFileNameT)): also. 
                for x in splitFileNameT:
                    if tempT != None:
                        temp2T = tempT
                    tempT = x
                    if temp2T != None:
                        if checkFileNameT == None:
                            checkFileNameT = temp2T
                        else:
                            checkFileNameT = checkFileNameT + temp2T
                    fileNameP = checkFileNameT

                if checkFileNameT == None:
                    checkFileNameT = string.split(checkFileT, ".")[0]
                    printDebugNoLock(lineNum() + str(checkFileNameT) ,3)

                currentParamT += 1
                skipT = 1
                continue
            else:
                currentParamT += 1
                continue



        elif argT == '-h': # help
            printHelp()

            sys.exit()

        else:
            listOfFilesT = []
            listOfFilesT.append(argT)
            currentParamT += 1
            #\033[32;1;1m[+]\033[0m 
            printInfo("\033[31;1;1m[-]\033[0m Invalid Commandline Parameter: " + str(argT), 1)
            printInfo("\033[31;1;1m[-]\033[0m Will exit program.... ", 1)

            printHelp()
            
            sys.exit()

    if (fileNameT != None):
        fileNameP = fileNameT
        fileNameP = string.replace(fileNameP,'/','')
        fileNameP = string.replace(fileNameP,'\\','')
        fileNameP = string.replace(fileNameP,':',"_")
        fileNameT = fileNameP

    return  fileNameT, listOfFilesT, topLevelDirT


##
# main function, where good things happen!
#
def main():

    global fileListG

    retValT = False
    

    fileNameT = None
    

    alertConfigFileT = outputFilesG.openAlertConfigFile()


    if outputFilesG.alertConfigFileM != None:
        printInfo('Loading Alert Config File: ' + "alertconfig.cfg",2)

        outputFilesG.loadAlertConfigFile()

    else:
        printInfo('Couldn\'t open alertconfig.cfg. Exiting...',1)
        sys.exit()

    fileNameT, listOfFilesT, topLevelDirT = processCommandLine(fileNameT)

    outputFilesG.setFileNamePrefix(fileNameT) # set the prefix of the output files generated.
    outputFilesG.determineFilenamePrefix()
    outputFilesG.determineOutputDirectory()
    outputFilesG.determineNoClobberValue()

    paramsG.alertConfigM.DisplayProfile()

    if listOfFilesT != None:
    
        fileListG = listOfFilesT
    else:
        printInfo("\033[31;1;1m[-]\033[0m No Input Directory Detected: ", 1)
        return False

    if paramsG.generateHashesM == True:
        generateHashes(listOfFilesT)
        retValT = True
    elif paramsG.checkHashesM == True:
        startedNotification()
        while(1==1):
            checkHashes(listOfFilesT)
            printInfo("\033[32;1;1m[+]\033[0m Checking Hashes...",1)
            auditFileHashes(listOfFilesT)
            if paramsG.monitorModeM == False:
                break
            printInfo("\033[32;1;1m[+]\033[0m Sleeping for " + str(paramsG.monitorModeSleepM) + " seconds...", 1)
            time.sleep(paramsG.monitorModeSleepM)
            # Need to rebuild the file list, just in case a file has appeared.
            listOfFilesT, topLevelDirT = getAllFilesInDirectory(topLevelDirT, paramsG.maxDepthM)
            printDebugNoLock(lineNum() + str(topLevelDirT),4)
        retValT = True
    else:
        print("\n\033[32;1;1m[+]\033[0m Passing...\n")
        retValT = True

    outputFilesG.closeFiles()

    return retValT

##
# Default function.
#
if __name__ == "__main__":

    if main() == True:
        printInfo("\033[32;1;1m[+]\033[0m Done!", 1)
    else:
        printInfo("\033[31;1;1m[-]\033[0m *** Processing Error!!!! ***\n ", 1)



## EOF ########################################################################
