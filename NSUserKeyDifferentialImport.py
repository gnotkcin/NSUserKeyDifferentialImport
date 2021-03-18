#!/usr/bin/env python

# BCG NSUserKeyDifferentialImport
# Development: MacDevOps@bcg.com
# Operations: DLPTeam@bcg.com
#
# Change Log
# tong.nick@bcg.com 06-FEB-2020 Created
# tong.nick@bcg.com 11-FEB-2020 Exception Handling for Crash Protection

# Summary: Imports user key values from NetSkope to JAMF.
#
# Description: NSUserKeyDifferentialImport fetches a list of all computer IDs 
# and names (jamfIdAndName) from JAMF and, for each jamfIdAndName, 
# instantiates the Computer() class, resulting in a single computer object 
# corresponding to each jamfIdAndName.
#
# Computer()'s initialization method fetches and assigns values to a number of 
# properties that may be of interest to the you, including:
# 
# jid (jamf computer_id)
# udid (jamf unique device identifier)
# name (jamf computer_name)
# email (jamf email_address)
# userkey (value from jamf extension attribute that stores the NetSkope user key)
# 
# Each computer object that has an empty userkey value is then stored in the 
# [computers] list, while computer objects with a non-empty userkey value are 
# discarded because those do not need to re-import a userkey value.
# 
# Once the [computers] list is populated with computer objects representing 
# each JAMF computer record having an empty userkey, NetSkope is queried for
# a userkey using the computer object's e-mail property value. If NetSkope
# returns a userkey, the corresponding computer object is is mutated by assigning 
# the returned value to the computer object's userkey property.
# 
# Once each computer object is updated with a userkey (or error(s) in the absence
# of a userkey), the list is iterated one last time to post the userkeys to JAMF.
# 
# Usage: Update values in the below Settings section. When testing, set the 
# recordLimit to a non-zero integer to avoid iterating over thousands of records.
# Additionally, set verboseMode to True when testing in order to log to stdout.
# When running in production, set recordLimit to 0 and verboseMode to False.

import sys
import argparse
import requests

################################################################################

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=('''NSUserKeyDifferentialImport differentially imports UserKeys from NetSkope into JAMF\n& NSUserKeyDifferentialImportHelper generates nsbranding.json configuration files\nfrom the imported UserKeys.\n\nTo configure this tool, run:\n\nNSUserKeyDifferentialImport.py --configure\n\nWhen testing the tool, enable verbose mode to log to stdout and set a finite limit\nto avoid processing all computer records:\n\nNSUserKeyDifferentialImport.py --limit 100 -v\n\nWhen running the tool as a scheduled job, do not pass any options - this ensures\nthat no sensitive information will be printed to stdout while processing all records:\n\nNSUserKeyDifferentialImport.py\n\nFor more information, visit: github.bcg.com/macdevops/NSUserKeyDifferentialImport'''), epilog='Copyright (c) 2020 The Boston Consulting Group, Inc.')

parser.add_argument("-c", "--configure", help="configure this tool", action="store_true")
parser.add_argument("-v", "--verbose", help="verbosely log to stdout", action="store_true")
parser.add_argument("--limit", help="max count of userkeys to fetch (int)")

if not len(sys.argv) > 1:
	parser.print_help()

args = parser.parse_args()

################################################################################

def optConfigure():
	print("optConfigure()")
	sys.exit("###optConfigure")

################################################################################

if args.verbose:
	verboseMode = True
else:
	verboseMode = False

if args.limit != None:
	recordLimit = args.limit
else:
	recordLimit = 0

if args.configure:
	optConfigure()

sys.exit("###")

################################################################################
# Settings: Edit Variables in This Section #####################################
################################################################################

# recordLimit = 100 # 0 for no limit. Will find up to this number of empty-userkey JAMF records before stopping
# verboseMode = True # Boolean keywords are case sensitive: True or False must be capitalized

nsEnv    = 'REDACTED' #
nsDomain = 'goskope.com'
nsToken  = 'REDACTED'

jamfEnv    = 'REDACTED' #
jamfDomain = 'bcg.com'
jamfToken  = 'REDACTED=='

jamfXattr  = 'netskopeUserKey' # Name of the JAMF extension attribute field that does/will contain NetSkope UserKey values

################################################################################
# End Settings: Generally, anything below this line does not need to be edited #
################################################################################

nsBaseURL = "https://%s.%s/api" % (nsEnv, nsDomain)
nsApiVersion = "v1"
nsUserConfigAPI = nsBaseURL + "/" + nsApiVersion + "/userconfig"

jamfBaseURL = "https://%s.%s/JSSResource" % (jamfEnv, jamfDomain)
jamfComputersAPI = jamfBaseURL + "/computers"
jamfComputerPropertiesByIdAPI = jamfBaseURL + "/computers/id"

jamfHeaders = {
	'Accept': "application/json", # JAMF allows JSON or XML download, so using JSON for convenience
	'Content-Type': "application/xml", # JAMF only allows XML upload (no JSON) as of January 2020
	'Authorization': "Basic %s" % (jamfToken),
	'Accept-Encoding': "gzip, deflate",
	'Connection': "keep-alive",
	'cache-control': "no-cache"
	}

################################################################################

def getFromNetSkope(url, nparams):
	try:
		r = requests.request("GET", url, params=nparams, timeout=5)
		r.raise_for_status()
		return r
	except requests.exceptions.RequestException as err:
		print("CHECK NETWORK CONNECTION \n")
		if verboseMode == True:
			print("RequestException on getFromNetSkope(url: %s, params: %s): %s \n" % (url, nparams, err))
	except requests.exceptions.HTTPError as err:
		if verboseMode == True:
			print("HTTPError on getFromNetSkope(url: %s, params: %s): %s \n" % (url, nparams, err))
	except requests.exceptions.ConnectionError as err:
		if verboseMode == True:
			print("ConnectionError on getFromNetSkope(url: %s, params: %s): %s  \n" % (url, nparams, err))
	except requests.exceptions.Timeout as err:
		if verboseMode == True:
			print("Timeout on getFromNetSkope(url: %s, params: %s): %s \n" % (url, nparams, err))
	except requests.exceptions.SSLError as err:
		if verboseMode == True:
			print("SSLError on getFromNetSkope(url: %s, headers: %s): %s \n" % (url, nparams, err))
	except Exception as err:
		if verboseMode == True:
			print("Unrecognized Exception on getFromNetSkope(url: %s, headers: %s): %s \n" % (url, nparams, err))

################################################################################

def getFromJamf(url, jheaders):
	try:
		r = requests.request("GET", url, headers=jheaders, timeout=5)
		r.raise_for_status()
		return r
	except requests.exceptions.RequestException as err:
		print("CHECK NETWORK CONNECTION \n")
		if verboseMode == True:
			print("RequestException on getFromJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.HTTPError as err:
		if verboseMode == True:
			print("HTTPError on getFromJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.ConnectionError as err:
		if verboseMode == True:
			print("ConnectionError on getFromJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.Timeout as err:
		if verboseMode == True:
			print("Timeout on getFromJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.SSLError as err:
		if verboseMode == True:
			print("SSLError on getFromJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except Exception as err:
		if verboseMode == True:
			print("Unrecognized Exception on getFromJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))

################################################################################

def putToJamf(url, jheaders, jdata):
	# requests.request("PUT", jamfComputerPropertiesByIdAPI + "/%s/subset/extensionattributes" % (self.jid), data=xml, headers=jamfHeaders)
	try:
		r = requests.request("PUT", url, headers=jheaders, data=jdata, timeout=10)
		r.raise_for_status()
		return r
	except requests.exceptions.RequestException as err:
		print("CHECK NETWORK CONNECTION \n")
		if verboseMode == True:
			print("RequestException on putToJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.HTTPError as err:
		if verboseMode == True:
			print("HTTPError on putToJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.ConnectionError as err:
		if verboseMode == True:
			print("ConnectionError on putToJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.Timeout as err:
		if verboseMode == True:
			print("Timeout on putToJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except requests.exceptions.SSLError as err:
		if verboseMode == True:
			print("SSLError on putToJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))
	except Exception as err:
		if verboseMode == True:
			print("Unrecognized Exception on putToJamf(url: %s, headers: %s): %s \n" % (url, jheaders, err))

################################################################################

computers = []

################################################################################

class Computer:
	def __init__(self, jamfIdAndName):
		
		self.jamfComputerPropertiesByIdAPI = jamfComputerPropertiesByIdAPI
		self.jamfIdAndName            = jamfIdAndName
		self.jid      = jamfIdAndName['id']
		self.name     = jamfIdAndName['name']
		
		self.jamfComputerPropertiesByIdAPIResponse = getFromJamf(jamfComputerPropertiesByIdAPI + "/%s" % (jamfIdAndName['id']), jamfHeaders)
		
		if self.jamfComputerPropertiesByIdAPIResponse is not None:
			self.jamfComputerPropertiesByIdAPIResponseJSON = self.jamfComputerPropertiesByIdAPIResponse.json()
			self.udid     = self.jamfComputerPropertiesByIdAPIResponseJSON['computer']['general']['udid']
			self.email    = self.jamfComputerPropertiesByIdAPIResponseJSON['computer']['location']['email_address']
			self.errors   = ''
			
			xattrIndex=0
			for xattr in self.jamfComputerPropertiesByIdAPIResponseJSON['computer']['extension_attributes']:
				self.xattrName  = self.jamfComputerPropertiesByIdAPIResponseJSON['computer']['extension_attributes'][xattrIndex]['name']
				if self.xattrName == jamfXattr:
					self.userkey = self.jamfComputerPropertiesByIdAPIResponseJSON['computer']['extension_attributes'][xattrIndex]['value']
					break
				xattrIndex = xattrIndex + 1
		else:
			if verboseMode == True:
				print ("Warning: Unable to retrieve and assign properties to Computer(%s, %s), it will be discarded \n" % (jamfIdAndName['id'], jamfIdAndName['name']))
			
	
	def printObjAddress(self):
		print(hex(id(self)))
	
	def fillUserKeyFromNetSkope(self):
		self.nsQueryParams = {'token': nsToken, 'email': self.email, 'configtype': "agent"}
		self.nsAgentUserConfigResponse = getFromNetSkope(nsUserConfigAPI, self.nsQueryParams)
		if self.nsAgentUserConfigResponse is not None:
			self.nsAgentUserConfigResponseJSON = self.nsAgentUserConfigResponse.json()
			self.nsStatus = self.nsAgentUserConfigResponseJSON['status']
			if self.nsStatus == 'success':
				self.userkey = self.nsAgentUserConfigResponseJSON['data']['brandingdata']['UserKey']
				self.nsErrors = ['']
			else:
				self.nsErrors = self.nsAgentUserConfigResponseJSON['errors']
		else:
			self.nsStatus = 'undefined'
			self.nsErrors = ['']
		return self.nsStatus, self.nsErrors
	
	def updateJamf(self):		
		# At the time of this writing (Jan 2020), JAMF only supports XML upload (JSON only supported for download, not upload)
		xml = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><computer><extension_attributes><attribute><name>%s</name><value>%s</value></attribute></extension_attributes></computer>' % (jamfXattr, self.userkey)

		self.jamfPutXattrByIdAPIResponse = putToJamf(jamfComputerPropertiesByIdAPI + "/%s/subset/extensionattributes" % (self.jid), jamfHeaders, xml)
		
		if verboseMode == True:
			print("################################################################################\n")
			print("OBJECT %s\n" % (hex(id(self))))
			print("Object Properties (ID, UDID, Name, Email, UserKey, Errors):\n")
			print("%s, %s, %s, %s, %s, %s\n" % (self.jid, self.udid, self.name, self.email, self.userkey, self.errors))
			print("API Endpoint URL:")
			print(jamfComputerPropertiesByIdAPI + "/%s/subset/extensionattributes\n" % (self.jid))
			print("XML Body of PUT Request:")
			print("%s\n" % (xml))
			print("Response Body:")
			print("%s\n" % (self.jamfPutXattrByIdAPIResponse))
			print("Response Status:")
			if hasattr(self.jamfPutXattrByIdAPIResponse, 'status_code'):
				print("%s\n" % (self.jamfPutXattrByIdAPIResponse.status_code))
			else:
				print("999 (jamfPutXattrByIdAPIResponse has no status_code attribute)")

################################################################################

# jamfComputersAPIResponse = requests.request("GET", jamfComputersAPI, headers=jamfHeaders)
jamfComputersAPIResponse = getFromJamf(jamfComputersAPI, jamfHeaders)
if jamfComputersAPIResponse is not None:
	jamfComputersAPIResponseJSON = jamfComputersAPIResponse.json()
else:
	sys.exit("Fatal: Exiting on empty response from getFromJamf(url: %s, headers: %s)" % (jamfComputersAPI, jamfHeaders))

i=0
for jamfIdAndName in jamfComputersAPIResponseJSON['computers']:
	computer = Computer(jamfIdAndName)
	if hasattr(computer, 'userkey') == True:
		if computer.userkey == '':
			computers.append(computer)
			if verboseMode == True:
				print ("Info: Inserted Computer(%s, %s, %s, %s, %s, %s) at computers[%s] because it does not have pre-existing nsUserKey \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors, i))
			i=i+1
		else:
			if verboseMode == True:
				print ("Info: Discarded Computer(%s, %s, %s, %s, %s, %s) because it has a pre-existing nsUserKey \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))	
		if recordLimit > 0:
			if i == recordLimit:
				break
	else:
		if verboseMode == True:
			print ("Warning: Discarded Computer(%s, %s) because Computer().__init__ was unable to fetch and assign properties \n" % (computer.jid, computer.name))

################################################################################

for computer in computers:
	
	nsStatus, nsErrors = computer.fillUserKeyFromNetSkope()
	
	if nsStatus == 'success':
		if len(computer.userkey) > 0:
			if len(computer.userkey) == 20:
				if verboseMode == True:
					print ("Info: NetSkope Returned UserKey of Expected Length (20) for Computer(%s, %s, %s, %s, %s, %s), which is now queued for submission to JAMF \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
			else:
				if verboseMode == True:
					print ("Warning: NetSkope Returned UserKey of Unexpected Length (!=20) for Computer(%s, %s, %s, %s, %s, %s), which is nonetheless now queued for submission to JAMF \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
		else:
			computer.errors = ['nsQueriedButReturnedWithEmptyUserKey']
			if verboseMode == True:
				print ("Error: NetSkope Returned UserKey of Zero Length (0) for Computer(%s, %s, %s, %s, %s, %s) \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
	elif nsStatus == 'error':
		# nsErrors = nsAgentUserConfigResponseJSON['errors']
		if 'Error Processing Request' in nsErrors:
			computer.errors = ['nsQueriedButReturnedEmailNotFound']
			if verboseMode == True:
				print ("Error: NetSkope Returned Error for Computer(%s, %s, %s, %s, %s, %s) \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
		else:
			computer.errors = ['nsQueriedButReturnedWithUnrecognizedError']
			if verboseMode == True:
				print("Error: NetSkope Returned Unrecognized Error for Computer(%s, %s, %s, %s, %s, %s) \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
	elif nsStatus == 'undefined':
		print("HINT: CHECK FOR INTERMITTENT NETWORK CONNECTIVITY \n")
		if verboseMode == True:
			print("Error: NetSkope Did Not Return for Computer(%s, %s, %s, %s, %s, %s) \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
	else:
		computer.errors = ['nsQueriedButReturnedWithUnrecognizedStatus']
		if verboseMode == True:
			print("Error: NetSkope Returned Unrecognized Status of %s for Computer(%s, %s, %s, %s, %s, %s) \n" % (nsStatus, computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))

################################################################################

for computer in computers:
	if hasattr(computer, 'userkey'):
		if len(computer.userkey) == 20:
			computer.updateJamf()
		else:
			if verboseMode == True:
				print("################################################################################")
				print("Error: Did not update JAMF UserKey for Computer(%s, %s, %s, %s, %s, %s) because the length of the userkey value is not equal to 20 \n" % (computer.jid, computer.udid, computer.name, computer.email, computer.userkey, computer.errors))
	else:
		if verboseMode == True:
			print("################################################################################")
			print("Error: Did not update JAMF UserKey for Computer(%s, %s) because the computer.userkey attribute does not exist \n" % (computer.jid, computer.name))

################################################################################
