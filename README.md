This is a Python script for AppResponse 11 utilities (ar11_utilities.py) that allows bulk operations across a list of appliances, assuming they have the same username/password. (Of course, the script could be modified to pull username and password per appliance, if required.) This is a short-term workaround for customers with a large number of appliances while they wait for Portal central management support of these features.

Currently, the script supports:
•	Automated creation and pull of backup configurations from appliances
•	Reporting of Capture Job durations
•	SAML configuration export and import
•	Local user export, import, and deletion
•	Role export, import and deletion
•	Web server cipher and TLS version settings update

I have also included example files showing the formats of the associated actions. (Some actions, such as delete, simply require one object name per line. Other actions, such as import, require a more complete JSON representation.  In the cases of roles, a format based on the current Web UI visualization (formatted line per role) was used.) See below for the script execution examples.


*****

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action report_job_durations

Output:
Appliance 10.1.150.220
['Job Name', 'State', 'Duration']
['mida-lab-default_job', 'RUNNING', '18 days, 14 hours, 13 minutes']


CLI# python ar11_utilities.py --hostnamelist arxlist --username jkraenzle --password <password> --action report_job_durations

            This is the only command with an example of how to loop the command execution across multiple appliances

            arxlist:
            appresponseorange.riverbed-demo.com
            appresponseblue.riverbed-demo.com
            appresponseblack.riverbed-demo.com

Output:
Status code was 403
Error: b'{"error_id":"AUTH_FORBIDDEN","error_text":"Forbidden"}'
Appliance appresponseorange.riverbed-demo.com
No Capture Jobs found on appliance

Appliance appresponseblue.riverbed-demo.com
['Job Name', 'State', 'Duration']
['default_job', 'RUNNING', '4 days, 13 hours, 43 minutes']

Status code was 401
Error b'{"error_id": "ACCESS_DENIED", "error_text": "Not authorized to perform the requested operation"}'
Failed to login to appresponseblack.riverbed-demo.com

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action roles_export --actionfile roles_export

roles_export:
# Roles on appliance 10.1.150.220
System Administrator, System Administrator, All objects:RW,Application configuration:RW,Job configuration:RW,Network packets:RW,RBAC configuration:RW,System configuration:RW
User, , All objects:RO,Application configuration:RW,Job configuration:RW,Network packets:RW,System configuration:RO
Tester, , All objects:RO

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action roles_import --actionfile roles_import

roles_import:
# Roles on appliance 10.1.150.220
System Administrator, System Administrator, All objects:RW,Application configuration:RW,Job configuration:RW,Network packets:RW,RBAC configuration:RW,System configuration:RW
User, , All objects:RO,Application configuration:RW,Job configuration:RW,Network packets:RW,System configuration:RO
Tester, , All objects:RO
Manager, , All objects:RO,System configuration:RO

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action roles_delete --actionfile roles_delete

roles_delete:
# This is an example file, with a comment, on how to list roles for deletion
Manager

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action saml_export --actionfile saml_export

saml_export:
{"sign_auth_requests": false, "enabled": false, "fqdn": "", "require_signed_assertions": false, "roles_attr": "memberOf", "idp_metadata": "<?xml version=\"1.0\"?>\r\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://capriza.github.io/samling/samling.html\">\r\n  <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\r\n    <md:KeyDescriptor use=\"signing\">\r\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\r\n </ds:KeyInfo>\r\n    </md:KeyDescriptor>\r\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\r\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://capriza.github.io/samling/samling.html\"/>\r\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://capriza.github.io/samling/samling.html\"/>\r\n  </md:IDPSSODescriptor>\r\n</md:EntityDescriptor>", "username_attr": ""}

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action saml_import --actionfile saml_import

saml_import:
{"sign_auth_requests": false, "enabled": false, "fqdn": "", "require_signed_assertions": false, "roles_attr": "memberOf", "idp_metadata": "", "username_attr": ""}

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action users_export --actionfile users_export

users_export:
{"items": [{"status": "active", "password": {"change_allowed_in": 0, "locks_on": 0, "expires_on": 0}, "enable": true, "account_never_inactive": false, "name": "admin", "roles": [202], "logged_in": true, "login_failure": {"count": 0, "source": "N/A", "date": 0}, "password_never_expires": false, "description": ""}, {"status": "active", "password": {"change_allowed_in": 0, "locks_on": 0, "expires_on": 0}, "enable": true, "account_never_inactive": false, "name": "riverbed", "roles": [203], "logged_in": false, "login_failure": {"count": 0, "source": "N/A", "date": 0}, "password_never_expires": false, "description": ""}]}

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action users_import --actionfile users_import 

users_import:
{"items": [{"status": "active", "new_password": {"cleartext": "test"} , "password": {"change_allowed_in": 0, "locks_on": 0, "expires_on": 0}, "enable": true, "account_never_inactive": false, "name": "test", "roles": [204], "logged_in": true, "login_failure": {"count": 0, "source": "N/A", "date": 0}, "password_never_expires": false, "description": "Test user"}]}

CLI# python ar11_utilities.py --hostname 10.1.150.220 --username admin --password admin --action users_delete --actionfile users_delete

users_delete:
test

