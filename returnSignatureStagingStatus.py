#This script requires python 3
#To run 
#python3 <scriptname>.py <asm policy name>
#This script takes an asm policy name as an argument and will loop through that policy's signatures and 
# disable staging/"Perform Staging" under Security->Application Security->Attack Signatures->Policy Attack Signature Properties

#Fyi, if you want to see the json output nicely indented, eg
#asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
#print(json.dumps(asmPoliciesData.json(),indent=2))

import requests, re, argparse
import json, sys
requests.packages.urllib3.disable_warnings() 

#Globals, 
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://10.4.6.10'
#End configurable globals

asmPoliciesPath = '/mgmt/tm/asm/policies/'
f5AuthHeaderName = 'X-F5-Auth-Token'
f5RestApiAuthPath = '/mgmt/shared/authn/login'
asmSignaturesPath = '/mgmt/tm/asm/signatures?options=non-default-properties'
disableSigStagingJson = '{"performStaging":"false"}'
applyPolicyUrl = host  + '/mgmt/tm/asm/tasks/apply-policy'
policyId = ''
f5AuthToken = ''
authDataJson = '{"username":"' + adminUser + '", "password":"' + adminPass + '","loginProviderName": "tmos"}'


#Content type needed to tell rest server what type of content is being sent
restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Url to all policies
asmPoliciesUrl = host + asmPoliciesPath
asmRestApiAuthUrl = host + f5RestApiAuthPath
#Global to save the actual url of the asm policy
asmPolicyIdUrl = ''
#If the policy specified as the argument is found
asmPolicyFoundStatus = 0

#Require Python v3 or greater
if sys.version_info[:3] < (3,0,0):
    print('requires Python >= 3.0.0')
    sys.exit(1)


parser = argparse.ArgumentParser()
parser.add_argument('--performStaging',choices=['False','True'],required=True)
#args = parser.parse_args()
#print(args.stagingStatus)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--allPolicies',action='store_true')
group.add_argument('--policy')
args = parser.parse_args()
wafPolicyName = args.policy
signatureStagingStatus = args.performStaging
print(str(type(signatureStagingStatus)))
print(wafPolicyName)
print(args.allPolicies)


###Get the name of the policy passed as a command line arg
#if len(sys.argv) > 1:

#	wafPolicyName=sys.argv[1]
	
#else:
    
#    print('Error requires asm policy name')
#   sys.exit()
##

#Get all asm policies to get the policy id of name passed as the argument
#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy>
asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Load json output into a python dictionary format
asmPoliciesDataJson = json.loads(asmPoliciesData.text)

def getRestApiAuthToken():

	authResponse = requests.post(url=asmRestApiAuthUrl,headers=restHeaders,data=authDataJson,verify=False)
	print(authResponse.text)
	authResponseJson = json.loads(authResponse.text)
	print(authResponseJson['token']['token'])
	restHeaders[f5AuthHeaderName] = authResponseJson['token']['token']

def wafReturnPolicyIdFromName(wafPolicyName):

	asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

	#Load json output into a python dictionary format
	asmPoliciesDataJson = json.loads(asmPoliciesData.text)

	#Loop through each policy to find which one equals the command line argument
	for policy in asmPoliciesDataJson['items']:
	
		#Check to find the policy 
		if (policy['name'] == wafPolicyName):
		
			#If found
			policyId = policy['id'] 
		
			return policyId

def printPolicySignatureBasedOnStagingStatus(wafPolicyName,signatureStagingStatus):

		wafPolicyId = wafReturnPolicyIdFromName(wafPolicyName)
		asmPolicyIdUrl = asmPoliciesUrl + wafPolicyId
		asmPolicySignaturesUrl = asmPoliciesUrl + wafPolicyId + '/signatures/'
		
		#Get the policy's signatures
		#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy>
		asmPolicySignatureData = requests.get(url=asmPolicySignaturesUrl,headers=restHeaders,verify=False)
		asmPolicySignatureDataJson = json.loads(asmPolicySignatureData.text)
		
		for item in asmPolicySignatureDataJson['items']:
		
			#print(str(type(item['performStaging'])))
			
			if str(item['performStaging']) == signatureStagingStatus:
			
				print(item)		

def printAllPoliciesSignatureBasedOnStagingStatus():
	
	asmPolicyData = requests.get(url=asmPoliciesUrl,headers=restHeaders,verify=False)
	asmPolicyDataJson = json.loads(asmPolicyData.text)
	
	#print(json.dumps(asmPolicyDataJson,indent=2))
	
	for policy in asmPolicyDataJson['items']:

		print(policy['id'])
		
		asmPolicySignaturesUrl = asmPoliciesUrl + policy['id'] + '/signatures/'
		
		#Get the policy's signatures
		#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy>
		asmPolicySignatureData = requests.get(url=asmPolicySignaturesUrl,headers=restHeaders,verify=False)
		asmPolicySignatureDataJson = json.loads(asmPolicySignatureData.text)
		
		for item in asmPolicySignatureDataJson['items']:
		
			#print(str(type(item['performStaging'])))
			
			if str(item['performStaging']) == signatureStagingStatus:
			
				print(item)		
		
getRestApiAuthToken()		
#print(wafReturnPolicyIdFromName(wafPolicyName))		

if args.allPolicies:

	printAllPoliciesSignatureBasedOnStagingStatus()

elif wafPolicyName != "None":

	printPolicySignatureBasedOnStagingStatus(wafPolicyName,signatureStagingStatus)	
		

		
"""		
		
		asmPolicyIdUrl = asmPoliciesUrl + policy['id']
		asmPolicySignaturesUrl = asmPoliciesUrl + policy['id'] + '/signatures/'
		
		#Get the policy's signatures
		#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy>
		asmPolicySignatureData = requests.get(url=asmPolicySignaturesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		asmPolicySignatureDataJson = json.loads(asmPolicySignatureData.text)
		print(json.dumps(asmPolicySignatureDataJson,indent=2))
		#Loop through each signature, disbaling the performStaging variable
		#for policySig in asmPolicySignatureDataJson['items']:
		
			#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures?options=non-default-properties
		#	asmPolicySignatureUrl = asmPolicySignaturesUrl + policySig['id']
			
			#curl -sk -X PATCH -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy> -d '{"performStaging":"false"}' -H '"Content-Type":"application/json"'
		#	asmPolicySigResult = requests.patch(url=asmPolicySignatureUrl,data=disableSigStagingJson,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#If the policy name was not found, exit						
if asmPolicyFoundStatus == 0:

		sys.exit("No policy by that name found")

"""