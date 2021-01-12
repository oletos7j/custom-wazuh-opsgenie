#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2020, Wazuh Inc.
# December 1, 2020.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
from __future__ import print_function
from pprint import pprint
import json
import sys
import time
import opsgenie_sdk
from opsgenie_sdk.rest import ApiException

def main(args):
    alert_file_location = args[1]
    configuration = opsgenie_sdk.Configuration()
    configuration.api_key['Authorization'] = args[2]
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)

    description = json_alert['rule']['description']
    level = json_alert['rule']['level']
    agentname = json_alert['agent']['name']
    ip = json_alert['agent']['ip']
    full_log = json_alert['full_log']
    location = json_alert['location']
    tactic = json_alert['rule']['mitre']['tactic']
    tech = json_alert['rule']['mitre']['technique']
    source = json_alert['manager']['name']
    t = time.strptime(json_alert['timestamp'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
    timestamp = time.strftime('%c', t)

    api_instance = opsgenie_sdk.AlertApi(opsgenie_sdk.ApiClient(configuration))
    create_alert_payload = opsgenie_sdk.CreateAlertPayload(
        message='{0} - alert level {1}: {2}'.format(agentname, level, description),
        description="""
    On {a}, an event from {b} ({h}) triggered the Wazuh rule "{c}".
    
    This event type is {f} via {g}. It was identified in the {e} log.
    
    Full log: {d}
    """.format(a=timestamp, b=agentname, c=description, d=full_log, e=location, f=tactic, g=tech, h=ip),
        source=source,
        tags=['wazuh','ossec'])

    try:
        api_response = api_instance.create_alert(create_alert_payload)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling AlertApi->create_alert: %s\n" % e)

if __name__ == "__main__":
    main(sys.argv)

