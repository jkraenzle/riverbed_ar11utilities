# Python-wrapped REST API utilities for AppResponse 11

import os
import sys
import requests
import time
import argparse
import json
import getpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Avoid warnings for insecure certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

AR11_UTILITIES_ACTIONS = ["data_layout", \
			  "interface_summary", \
			  "packet_download", \
			  "pull_backup", \
			  "report_job_durations", \
			  "roles_delete", \
			  "roles_export", \
			  "roles_import", \
			  "saml_export", \
			  "saml_import", \
			  "saml_spmetadata_download", \
			  "users_delete", \
			  "users_export", \
			  "users_import", \
			  "web_server_settings_export", \
			  "web_server_settings_import"]

##### HELPER FUNCTIONS
### jkraenzle: Update to be used by each call
# Run REST APIs to appliance and return result
# Assume 'payload' is JSON formatted
def ar11_rest_api (action, path, appliance, access_token, version, payload = None):

	url = "https://" + appliance + path 

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	if (action == "GET"):
		r = requests.get (url, headers=headers, verify=False)
	elif (action == "POST"):
		r = requests.post (url, headers=headers, data=json.dumps (payload), verify=False)
	elif (action == "PUT"):
		r = requests.put (url, headers=headers, data=json.dumps (payload), verify=False)
	elif (action == "DELETE"):
		r = requests.delete (url, headers=headers, verify=False)

	if (r.status_code not in [200, 201, 204]):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
		result = None
	else:
		if (("Content-Type" in r.headers.keys ()) and ("application/json" in r.headers ["Content-Type"])):
			result = json.loads (r.content) 
		elif (("Content-Type" in r.headers.keys ()) and ("application/x-gzip" in r.headers ["Content-Type"])):
			result = r.content
		else:
			result = r.text

	return result 


##### ACTION - report_job_durations

# Helper function to report duration of Capture Jobs from start and end time
def ar11_capture_job_durations(jobs):
	output = []
	output.append(['Job Name', 'State', 'Duration'])
	
	for j in jobs:
		job_name = j['config']['name']	
		job_id = j['id']
		status = j['state']['status']
		state = status['state']
		start_time = status['packet_start_time']
		end_time = status['packet_end_time']
		duration = int(float(end_time) - float(start_time))
		days = round(duration / (60 * 60 * 24))
		hours = round((duration % (60 * 60 * 24)) / (60 * 60))
		minutes = round(((duration % (60 * 60 * 24)) % (60 * 60)) / 60)
		duration_str = str (days) + " days, " + str(hours) + " hours, " + str(minutes) + " minutes"
		output.append([job_name, state, duration_str])

	return output

# REST API Python wrapper to request storage layout information
# URL https://<appliance>/api/npm.data_manager/2.1/layout
# Header: Authorization: Bearer <access_token>
def ar11_data_layout_get (appliance, access_token, version):

	url = "https://" + appliance + "/api/npm.data_manager/2.1/layout"

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	r = requests.get (url, headers=headers, verify=False)

	if (r.status_code != 200):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
		result = []
	else:
		result = json.loads (r.content) 

	return result 

def ar11_interface_summary_get (appliance, access_token, version):

        result = ar11_rest_api ("GET", "/api/npm.packet_capture/3.0/interfaces", appliance, access_token, version)

        return result

# REST API Python wrapper to create backup on appliance
def ar11_backup_create (appliance, access_token, version):

	# Kick off backup and give time to process
	payload = {"description": "Automated Backup"}

	backup_in_process = ar11_rest_api ("POST", "/api/npm.backup/1.0/backups", appliance, access_token, version, payload)

	# If backup creation failed, return upstream showing the failure
	if (backup_in_process == None):
		return None

	# Get backup id and sleep so there's time for backup to initially create
	backup_id = backup_in_process ["id"]
	time.sleep (5)

	# Keep checking if backup has completed
	backup_complete = False
	while (backup_complete == False):
		backup_list = ar11_rest_api ("GET", "/api/npm.backup/1.0/backups", appliance, access_token, version)

		backups = backup_list ["items"]
		found = False
		for backup in backups:
			if (backup ["id"] == backup_id):
				found = True
				if (backup ["status"] == "completed"):
					backup_complete = True

		# If backup "id" is not found on appliance
		if (found == False):
			print ("Error starting backup on %s" % appliance)
			return None
		elif (backup_complete == False):
			time.sleep (2)

	return backup_id

# REST API Python wrapper to download and delete automated backup
def ar11_backup_download_and_delete (appliance, access_token, version, backup_id):
	backup_file = ar11_rest_api ("GET", "/api/npm.backup/1.0/backups/items/" + backup_id + "/file", appliance, access_token, version)

	if (backup_file != None):
		with open (appliance + ".backup.tgz", "wb") as backup_f:
			backup_f.write (backup_file)
	
	ar11_rest_api ("DELETE", "/api/npm.backup/1.0/backups/items/" + backup_id, appliance, access_token, version)

	return

# REST API Python wrapper to create and pull backup from appliance
def ar11_backup_get (appliance, access_token, version):
	backup_id = ar11_backup_create (appliance, access_token, version)

	if (backup_id != None):
		ar11_backup_download_and_delete (appliance, access_token, version, backup_id)
		return True
	else:
		return False


# REST API Python wrapper to request Capture Job information
# URL https://<appliance>/api/npm.packet_capture/1.0/jobs
# Header: Authorization: Bearer <access_token>
def ar11_capture_jobs_get (appliance, access_token, version):

	if (version <= 11.4):
		url = "https://" + appliance + "/api/npm.packet_capture/1.0/jobs"
	else:
		url = "https://" + appliance + "/api/npm.packet_capture/2.0/jobs"
	
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	
	r = requests.get(url, headers=headers, verify=False)

	if (r.status_code != 200):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
		result = []
	else:
		result = json.loads(r.content)

	return result

def ar11_packet_download (appliance, access_token, version, settings_f):
	### jkraenzle: Yet to implement

	# Read settings and verify that they are valid for this appliance

	# Validate source (job by job name, etc.)

	# Confirm time range within Capture Job, etc.

	# Call to packet download with settings

	# Loop until packets have been downloaded

	return

##### ACTIONS - roles_export, roles_import, roles_delete 

def ar11_remote_auth_get (appliance, access_token, version):

	result = None

	if (version > 11.5):
		result = ar11_rest_api ("GET", "/api/mgmt.aaa/2.0/remote_authentication", appliance, access_token, version)

	return result

# URL: https://<appliance>/api/mgmt.aaa/2.0/roles/<id>
# PUT
def ar11_role_set (appliance, access_token, version, role):	
	if (version > 11.5):
		role_id = role ["id"]

		url = "https://" + appliance + "/api/mgmt.aaa/2.0/roles/" + str(role_id)
		
		bearer = "Bearer " + access_token
		headers = {"Content-Type":"application/json", "Authorization":bearer}

		r = requests.put (url, data=json.dumps(role), headers=headers, verify=False)

		return

# URL: https://<appliance>/api/mgmt.aaa/2.0/roles
# POST
def ar11_role_create (appliance, access_token, version, role):

	# Check if role name exists, and if so, delete? 
	
	if (version > 11.5):
		url = "https://" + appliance + "/api/mgmt.aaa/2.0/roles"
		
		bearer = "Bearer " + access_token
		headers = {"Content-Type":"application/json", "Authorization":bearer}

		r = requests.post (url, data=json.dumps(role), headers=headers, verify=False)

		return 

# REST API Python wrapper to get current roles
# URL: https://<appliance>/api/mgmt.aaa/2.0/roles
def ar11_roles_get (appliance, access_token, version):
	if (version > 11.5):
		url = "https://" + appliance + "/api/mgmt.aaa/2.0/roles"
		bearer = "Bearer " + access_token
		headers = {"Authorization":bearer}
		
		r = requests.get (url, headers=headers, verify=False)

		result = json.loads(r.content)

		return result["items"]

# Counterpart to from_file function
def ar11_roles_to_file (roles, export_f):

	for role in roles:
		export_f.write (str("%s, %s, " % (role["pretty_name"], role["description"])).rstrip('\n'))

		permissions = role["permissions"]
	
		i = 0
		for pg in permissions:
			if (pg["permission_group"] == "ALL_OBJECTS_ACCESS"):
				permission = "All objects"
			elif (pg["permission_group"] == "APP_CONFIG_ACCESS"):
				permission = "Application configuration"
			elif (pg["permission_group"] == "JOB_CONFIG_ACCESS"):
				permission = "Job configuration"
			elif (pg["permission_group"] == "PACKET_ACCESS"):
				permission = "Network packets"
			elif (pg["permission_group"] == "RBAC_CONFIG_ACCESS"):
				permission = "RBAC configuration"
			elif (pg["permission_group"] == "SYSTEM_MGMT_CONFIG_ACCESS"):
				permission = "System configuration"
			else:
				permission = "!!UNKNOWN PERMISSIONS!!"
				
			if (pg["operation"] == "read_only"):
				operation = "RO"
			elif (pg["operation"] == "read_write"):
				operation = "RW"
			else:
				operation = "NR"
		
			if (i != len (permissions) - 1):	
				export_f.write (str("%s:%s," % (permission, operation)).rstrip('\n'))
			else:
				export_f.write ("%s:%s\n" % (permission, operation))
			i+=1
		 
# Export current roles from AR11 appliance
# For now, assume file has been opened and this function uses the file at its current marker
def ar11_roles_export (appliance, access_token, version, export_f):

	# Make comment on current appliance from which these roles came
	export_f.write ("# Roles on appliance %s\n" % appliance)

	roles = ar11_roles_get (appliance, access_token, version)

	ar11_roles_to_file (roles, export_f)

	# Write a newline so there's space between each appliance export
	export_f.write ("\n")

	return

def ar11_roles_from_file (import_f):

	roles = []
	for line in import_f:
		comment_test = line
		if (len(comment_test.lstrip()) == 0):
			continue
		if (comment_test.lstrip()[0] == "#"):
			continue
		line_split = line.strip("\n").split (",")

		pretty_name = line_split[0].strip()
		description = line_split[1].strip()
		i = 2
		permissions = []
		while (i <= len(line_split) - 1):
			key_value = line_split [i].split(":")
			permission_key = key_value[0].strip ()
			if (len(key_value) == 2):
				if (permission_key == "All objects"):
					permission = "ALL_OBJECTS_ACCESS"
				elif (permission_key == "Application configuration"):
					permission = "APP_CONFIG_ACCESS"
				elif (permission_key  == "Job configuration"):
					permission = "JOB_CONFIG_ACCESS"
				elif (permission_key == "Network packets"):
					permission = "PACKET_ACCESS"
				elif (permission_key == "RBAC configuration"):
					permission = "RBAC_CONFIG_ACCESS"
				elif (permission_key == "System configuration"):
					permission = "SYSTEM_MGMT_CONFIG_ACCESS"
				else:
					permission = "!!UNKNOWN!!"

				if (key_value[1] == "RO"):
					operation = "read_only"
				elif (key_value[1] == "RW"):
					operation = "read_write"
				elif (key_value[1] == "NR"):
					operation = "no_read"
				else:
					operation = "!!UNKNOWN!!"

				if not(permission == "!!UNKNOWN!!" or operation == "!!UNKNOWN!!"):
					permissions.append({"permission_group":permission, "operation":operation})
				else:
					print ("Error reading permission %s: operation %s" % (permission_key, key_value[1]))
			i += 1

		role = {"description":description, "pretty_name":pretty_name, "permissions":permissions}
		
		roles.append (role)

	return roles

def ar11_roles_import (appliance, access_token, version, import_f):
	# Get list of roles from import file
	imported_roles = ar11_roles_from_file (import_f)

	# Get list of roles from appliance
	existing_roles = ar11_roles_get (appliance, access_token, version)

	set_list = []
	create_list = []
	i = 0
	for role in imported_roles:
		found = False
		id = 0

		for existing_role in existing_roles:
			if (role ["pretty_name"] == existing_role ["pretty_name"]):
				found = True
				role.update ({"id":existing_role["id"]})
		if (found):
			set_list.append(i)
		else:
			create_list.append(i)
		i += 1

	for item in set_list:
		role = imported_roles [item]
		ar11_role_set (appliance, access_token, version, role)

	for item in create_list:
		role = imported_roles [item]
		ar11_role_create (appliance, access_token, version, role)

	return

def ar11_role_names_from_file (import_f):

	roles = []
	for line in import_f:
		comment_test = line
		if (len(comment_test.lstrip()) == 0):
			continue
		if (comment_test.lstrip()[0] == "#"):
			continue
		role = line.strip("\n")
		roles.append(role)

	return roles

# URL: https://<appliance>/api/mgmt.aaa/2.0/roles/<id>
def ar11_role_delete (appliance, access_token, version, role_id):

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	url = "https://" + appliance + "/api/mgmt.aaa/2.0/roles/" + str(role_id)
	
	r = requests.delete (url, headers=headers, verify=False)
	
	return 

def ar11_roles_delete (appliance, access_token, version, delete_f):
	if (version > 11.5):
		# Get list of roles to delete
		roles_to_delete = ar11_role_names_from_file (delete_f)

		# Get list of roles from appliance
		existing_roles = ar11_roles_get (appliance, access_token, version)

		delete_list = []
		i = 0
		for role in roles_to_delete:
			found = False
			id = 0

			for existing_role in existing_roles:
				if (role == existing_role ["pretty_name"]):
					found = True
			if (found):
				delete_list.append(existing_role ["id"])
			else:
				print ("WARNING: Role %s did not exist on %s" % (role, appliance))

		# Loop through roles, deleting one at a time from appliance
		j = 0
		while (j < len(delete_list)):
			ar11_role_delete (appliance, access_token, version, delete_list[j])
			j += 1
	
	return

##### ACTIONS - saml_export, saml_import, saml_spmetadata_download

# For consistency, return configuration in JSON format
def ar11_saml_configuration_get (appliance, access_token, version):
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	url = "https://" + appliance + "/api/npm.saml/1.0/settings"

	r = requests.get (url, headers=headers, verify=False)

	result = json.loads(r.content)

	return result

def ar11_saml_configuration_set (appliance, access_token, version, saml_config):
	bearer = "Bearer " + access_token
	headers = {"Content-Type":"application/json", "Authorization":bearer}
	url = "https://" + appliance + "/api/npm.saml/1.0/settings"

	r = requests.put (url, headers=headers, json=saml_config, verify=False)

	if (r.status_code != 200):
		print ("SAML configuration returned with status code %d." % (r.status_code,))
		print (r.text)

	return

def ar11_saml_export (appliance, access_token, version, export_f):

	saml_config = ar11_saml_configuration_get (appliance, access_token, version)

	# Write file in text format
	export_f.write (json.dumps(saml_config))

	return

def ar11_saml_import (appliance, access_token, version, import_f):

	imported_txt = import_f.read ()
	#stripped_txt = imported_txt.strip("\n")
	#saml_config = stripped_txt.replace ("\\r\\n", "")
	#saml_config = replaced_txt.replace (" false", "\"False\"")	

	saml_config = json.loads (imported_txt)

	ar11_saml_configuration_set (appliance, access_token, version, saml_config)

	return

def ar11_saml_spmetadata_download (appliance, access_token, version):

	spmetadata_file = ar11_rest_api ("GET", "/saml/metadata", appliance, access_token, version)
	
	if (spmetadata_file != None):
		with open (appliance + "_spmetadata.xml", "a+") as spmetadata_f:
			spmetadata_f.write (json.dumps (spmetadata_file))
			return True
	else:
		print ("Did not return a file")
		return False

##### ACTIONS - users_delete, users_export, users_import

# URL: http://<appliance>/api/mgmt.aaa/2.0/users
def ar11_users_get (appliance, access_token, version):
	
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	url = "https://" + appliance + "/api/mgmt.aaa/2.0/users"

	r = requests.get (url, headers=headers, verify=False)

	result = json.loads(r.content)

	return result

def ar11_users_from_file (users_f):

	users = []
	for line in users_f:
		comment_test = line
		if (len(comment_test.lstrip()) == 0):
			continue
		if (comment_test.lstrip()[0] == "#"):
			continue
		user = line.strip("\n")
		users.append(user)

	return users

# URL: https://<appliance>/api/mgmt.aaa/2.0/users/<name>
def ar11_user_delete (appliance, access_token, version, username):
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	url = "https://" + appliance + "/api/mgmt.aaa/2.0/users/" + username
	
	r = requests.delete (url, headers=headers, verify=False)

	if (r.status_code != 204):
		print ("Failed to delete username %s" % (username))
		print ("Status code is %s" % (r.status_code))
		print ("Error: %s" % (r.content))

	return	

def ar11_users_delete (appliance, access_token, version, users_f):

	# Get current list of users; returns an array of dicts
	users_dict = ar11_users_get (appliance, access_token, version)
	users_list = users_dict ["items"]

	# Get list of users to delete
	users_to_delete_list = ar11_users_from_file (users_f)	

	# Confirm users exist before attempting to delete
	found_users_list = []
	for user in users_to_delete_list:
		found = False
		i = 0
		while (i < len (users_list)):
			existing_user = users_list [i]
			if (user == existing_user ["name"]):
				found = True
				break
			i += 1

		if (found == True):
			found_users_list.append (user)
		else:
			print ("User %s was not found on appliance %s" % (user, appliance))	

	for user in found_users_list:
		ar11_user_delete (appliance, access_token, version, user)		

def ar11_users_export (appliance, access_token, version, users_f):
	
	# Get current list of users; returns an array of dicts
	users_dict = ar11_users_get (appliance, access_token, version)

	# Write file in text format
	users_f.write (json.dumps (users_dict))

def ar11_user_set (appliance, access_token, version, imported_user):
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	url = "https://" + appliance + "/api/mgmt.aaa/2.0/users/" + str(imported_user["name"])
	
	r = requests.put (url, headers=headers, json=imported_user, verify=False)

	if (r.status_code != 200):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
	
	return

def ar11_user_create (appliance, access_token, version, imported_user):
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	url = "https://" + appliance + "/api/mgmt.aaa/2.0/users"
	
	r = requests.post (url, headers=headers, json=imported_user, verify=False)

	if (r.status_code != 201):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)

	return

def ar11_users_import (appliance, access_token, version, users_f):
	
	# Get list of users to update or create
	imported_txt = users_f.read ()

	imported_users_dict = json.loads (imported_txt)
	imported_users_list = imported_users_dict["items"]

	# Get list of existing users
	existing_users_dict = ar11_users_get (appliance, access_token, version)
	existing_users_list = existing_users_dict["items"]

	# Iterate over each imported user to see if that user already exists on this appliance
	for imported_user in imported_users_list:
		found = False
		for existing_user in existing_users_list:
			if (existing_user ["name"] == imported_user ["name"]):
				found = True
		if (found):
			ar11_user_set (appliance, access_token, version, imported_user)
		else:
			ar11_user_create (appliance, access_token, version, imported_user)		

def ar11_web_server_settings_export (appliance, access_token, version, settings_f):
	settings_dict = ar11_rest_api ("GET", "/api/npm.https/1.0/https", appliance, access_token, version)

	if (settings_dict == None):
		return False
	else:
		# Write file in text format
		settings_f.write (json.dumps (settings_dict))
		return True

def ar11_web_server_settings_import (appliance, access_token, version, settings_f):

	imported_txt = settings_f.read ()
	imported_settings_dict = json.loads (imported_txt)

	result = ar11_rest_api ("PUT", "/api/npm.https/1.0/https", appliance, access_token, version, imported_settings_dict)

	return True

##### GENERAL FUNCTIONS

# REST API Python wrapper to authenticate to the server (Login)
# URL: https://<appliance>/api/mgmt.aaa/1.0/token ; pre-version 11.6
# URL: https://<appliance>/api/mgmt.aaa/2.0/token ; version 11.6 or later
# Header: Content-Type:application/json
# Body: {"user_credentials":{"username":<username>, "password":<password>},"generate_refresh_token":"true"}
def ar11_authenticate (appliance, username, password, version):

	if (version <= 11.5):
		url = "https://" + appliance + "/api/mgmt.aaa/1.0/token"
	else:
		url = "https://" + appliance + "/api/mgmt.aaa/2.0/token"
	credentials = {"username":username, "password":password}
	payload = {"user_credentials":credentials, "generate_refresh_token":True}
	headers = {"Content-Type":"application/json"}

	r = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)

	if (r.status_code != 201):
		print ("Status code was %s" % r.status_code)
		print ("Error %s" % r.content)
		return None, None
	else:
		result = json.loads(r.content)

	return result["access_token"], result["refresh_token"]

# REST API Python wrapper to revoke refresh token (Logout)
# URL: https://<appliance>/api/mgmt.aaa/1.0/refresh_tokens/revoke
# Header: Authorization: Bearer <access_token>
def ar11_refresh_token_revoke (appliance, access_token, refresh_token):
	url = "https://" + appliance + "/api/mgmt.aaa/1.0/refresh_tokens/revoke"
	bearer = "Bearer " + access_token
	headers = {"Content-Type":"application/json", "Authorization":bearer}
	payload = {"refresh_token":refresh_token}

	r = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)

	return

# Helper function to get list of hostnames from input
def hostnamelist_get (hostnamelist):
	hostnamelist_f = open (hostnamelist, "r")

	output = []
	for row in hostnamelist_f:
		hostname = row.rstrip()
		output.append (hostname)

	hostnamelist_f.close ()

	return output

# REST API Python wrapper to request version information
# URL: https://<appliance>/api/common/1.0/info
# Header: AUthorization: Bearer <access_token>
def ar11_version_get (appliance, access_token, version):
	url = "https://" + appliance + "/api/common/1.0/info"
	
	r = requests.get (url, verify=False)

	result = json.loads(r.content)

	version_str = result["sw_version"]
	
	if "11.4" in version_str:
		return 11.4
	elif "11.5" in version_str:
		return 11.5
	elif "11.6" in version_str:
		return 11.6
	elif "11.7" in version_str:
		return 11.7
	elif "11.8" in version_str:
		return 11.8
	elif "11.9" in version_str:
		return 11.9

	return 11.9

def main():
	# set up arguments in appropriate variables
	parser = argparse.ArgumentParser (description="Python utilities to automate information collection or \
		 configuration tasks within AppResponse 11 environments")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse 11 appliance")
	parser.add_argument('--hostnamelist', help="File containing hostnames or IP addresses, one per line")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password for the username")
	parser.add_argument('--action', help="Action to perform: %s" % AR11_UTILITIES_ACTIONS)
	parser.add_argument('--actionfile', help="Settings file associated with action")
	args = parser.parse_args()

	# Check inputs for required data and prep variables
	if (args.hostname == None or args.hostname == "") and (args.hostnamelist == None or args.hostnamelist == ""):
		print ("Please specify a hostname using --hostname or a list of hostnames in a file using --hostnamelist")
		return
	if (args.username == None or args.username == ""):
		print ("Please specify a username using --username")
		return
	if (args.action == None or args.action == ""):
		print ("Please specify an action using --action")
		return

	# Use either hostname or hostname list; if both are accidentally specified, use hostname list
	if not(args.hostname == None or args.hostname == ""):
		hostnamelist = [args.hostname]
	elif not(args.hostnamelist == None or args.hostnamelist == ""):
		hostnamelist = hostnamelist_get (args.hostnamelist)

	# Check that action exist in set of known actions
	if not (args.action in AR11_UTILITIES_ACTIONS):
		print ("Action %s is unknown" % args.action)

	if (args.password == None or args.password == ""):
		print ("Please provide password for account %s" % args.username)
		password = getpass.getpass ()
	else:
		password = args.password

	# Loop through hosts, applying 'action'
	for hostname in hostnamelist:
		version = ar11_version_get (hostname, args.username, password)

		access_token, refresh_token = ar11_authenticate (hostname, args.username, password, version)

		if (access_token == None or access_token == ""):	
			print ("Failed to login to %s" % hostname)
			continue
		
		# ACTION - data_layout
		if (args.action == "data_layout"):
			layout = ar11_data_layout_get (hostname, access_token, version)
			
			data_sections = layout ["configuration"]["data_sections"]

			print ("%s:" % (hostname))
			if (len (data_sections) == 0):
				print ("No RAID configuration storage")
			for data_section in data_sections:
				if (data_section ["mode"] != ""):
					print ("%s\t%s\t%s" % (data_section ["id"], data_section ["model"], data_section ["mode"]))
			print ("")

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)
	
                # ACTION - interface_summary
		if (args.action == "interface_summary"):
			interface_summary = ar11_interface_summary_get (hostname, access_token, version)
			
			interfaces = interface_summary ["items"]

			print ("\t%s\t\t%s\t\t%s\t\t%s" % ("Name", "Status".ljust (8), "Packets - 1 hr".rjust (16), "Drops - 1 hr".rjust (16)))
			for interface in interfaces:
				print ("\t%s\t\t%s\t\t%s\t\t%s" % (interface ["name"], 
					str (interface ["state"]["status"]).ljust (8), 
					str (interface ["state"]["stats"]["packets_total"]["last_hour"]).rjust (16),
					str (interface ["state"]["stats"]["packets_dropped"]["last_hour"]).rjust (16)))

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)
	
		# ACTION - pull_backup
		elif (args.action == "pull_backup"):
			backup = ar11_backup_get (hostname, access_token, version)

			if (backup == True):
				print ("Backup for %s was successful!" % (hostname))
			else:
				print ("Backup for %s was unsuccessful!" % (hostname))

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - report_job_durations
		elif (args.action == "report_job_durations"):
			# Get capture jobs from appliance
			capture_jobs = ar11_capture_jobs_get (hostname, access_token, version)

			if (len(capture_jobs) > 0):
				output = ar11_capture_job_durations (capture_jobs["items"])
			else:
				output = ["No Capture Jobs found on appliance"]				

			print ("Appliance %s" % hostname)
			for row in output:
				print (row)
			print ("")

			# Okay to logout since only one action processed at a time
			ar11_refresh_token_revoke (hostname, access_token, refresh_token)
		
		# ACTION - roles_export
		elif (args.action == "roles_export"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename for role export in --actionfile parameter")
				return
			else:
				with open(args.actionfile, "a+") as roles_f:
					ar11_roles_export (hostname, access_token, version, roles_f) 

			# Okay to logout since only one action processed at a time
			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - roles_import
		elif (args.action == "roles_import"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename for role import in --actionfile parameter")
				return
			else:
				with open(args.actionfile, "r") as roles_f:
					ar11_roles_import (hostname, access_token, version, roles_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - roles_delete
		elif (args.action == "roles_delete"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename for roles to delete in --actionfile parameter, one role name per line")
				return
			else:
				with open(args.actionfile, "r") as roles_f:
					ar11_roles_delete (hostname, access_token, version, roles_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - saml_export
		elif (args.action == "saml_export"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename for SAML configuration to be exported")
				return
			else:
				with open(args.actionfile, "a+") as export_f:
					ar11_saml_export (hostname, access_token, version, export_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - saml_import
		elif (args.action == "saml_import"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename containing SAML configuration in JSON format")
				return
			else:
				with open(args.actionfile, "r") as import_f:
					ar11_saml_import (hostname, access_token, version, import_f)	

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		elif (args.action == "saml_spmetadata_download"):
			download = ar11_saml_spmetadata_download (hostname, access_token, version)
			
			if (download == True):
				print ("Download for %s was successful!" % (hostname))
			else:
				print ("Download for %s was unsuccessful!" % (hostname))

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - users_delete
		elif (args.action == "users_delete"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename containing the users to delete, one per line")
				return
			else:
				with open(args.actionfile, "r") as users_f:
					ar11_users_delete (hostname, access_token, version, users_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - users export
		elif (args.action == "users_export"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename to be used for export of user information")
				return
			else:
				with open(args.actionfile, "a+") as users_f:
					ar11_users_export (hostname, access_token, version, users_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - users import
		elif (args.action == "users_import"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify the filename containing the users to import in JSON format")
				return
			else:
				with open(args.actionfile, "r") as users_f:
					ar11_users_import (hostname, access_token, version, users_f)
		
			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - web server settings export
		elif (args.action == "web_server_settings_export"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename to be used for export of web server settings")
			else:
				with open (args.actionfile, "a+") as settings_f:
					ar11_web_server_settings_export (hostname, access_token, version, settings_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

		# ACTION - web server settings import
		elif (args.action == "web_server_settings_import"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify the filename containing the web server settings to import")
			else: 
				with open (args.actionfile, "r") as settings_f:
					ar11_web_server_settings_import (hostname, access_token, version, settings_f)

			ar11_refresh_token_revoke (hostname, access_token, refresh_token)

if __name__ == "__main__":
	main()
