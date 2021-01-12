# custom-wazuh-opsgenie
Uses the opsgenie-sdk to create opsgenie alerts from Wazuh (OSSEC fork).

## How to use
Review this guide -- https://documentation.wazuh.com/4.0/user-manual/manager/manual-integration.html

1. Pip install the opsgenie-sdk library.
2. Stage the script in the /var/ossec/integrations directory assigning it proper permissions.
3. Add an 'integration' block using the name (same name as the script and must start with "custom-"), the api_key, and the alert_format.
4. Restart the wazuh-manager.service.
