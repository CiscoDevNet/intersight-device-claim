#!/usr/bin/env python
"""
claim_device.py

Purpose:

Authors:
    David Soper (dspoer@cisco.com)
    John McDonough @movinalot
    Cisco Systems, Inc.
"""
# pylint: disable=invalid-name,redefined-outer-name

import json
import logging
import os
import sys
from time import sleep
import traceback
import requests
import yaml

import device_connector
from intersight_auth import IntersightAuth

DEBUG_SET = False

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def exception_print(err_msg, display_msg):
    """ Output Exception """
    logging.exception(display_msg)

    if DEBUG_SET:
        logging.exception('-' * 60)
        logging.exception(err_msg)
        logging.exception(traceback.print_stack)
        logging.exception('-' * 60)

def get_claim_config():
    """ Read in device claim Config File """

    CLAIM_CONFIG = None
    FILENAME = os.path.join(sys.path[0], sys.argv[1])

    logging.info('Reading config file: %s', FILENAME)
    try:
        with open(FILENAME, 'r') as file:
            if FILENAME.endswith('.json'):
                CLAIM_CONFIG = json.load(file)
            elif FILENAME.endswith('.yml'):
                CLAIM_CONFIG = yaml.load(file, Loader=yaml.FullLoader)
            else:
                logging.info(
                    'Unsupported file extension for configuration file: %s',
                    FILENAME
                )
    except IOError as io_error:
        sys.exit(io_error)
    return CLAIM_CONFIG

def get_device_claim_codes(device):
    """ Get device Claim Codes """

    try:
        result = dict(changed=False, msg="")
        dc_obj = device_connector.UcsDeviceConnector(device)

        if not dc_obj.logged_in:
            result['msg'] += "  Login error"
            return_code = 1
            logging.info(json.dumps(result))

        ro_json = dc_obj.configure_connector()
        logging.info(ro_json)
        if not ro_json['AdminState']:
            return_code = 1
            if ro_json.get('ApiError'):
                result['msg'] += ro_json['ApiError']
            logging.info(json.dumps(result))

        # wait for a connection to establish before checking claim state
        for _ in range(10):
            if ro_json['ConnectionState'] != 'Connected':
                sleep(1)
                ro_json = dc_obj.get_status()
            else:
                break

        result['msg'] += "  AdminState: %s" % ro_json['AdminState']
        result['msg'] += "  ConnectionState: %s" % ro_json['ConnectionState']
        result['msg'] += "  Claimed state: %s" % ro_json['AccountOwnershipState']

        if ro_json['ConnectionState'] != 'Connected':
            return_code = 1
            logging.info(json.dumps(result))

        if ro_json['AccountOwnershipState'] != 'Claimed':
            # attempt to claim
            (claim_resp, device_id, claim_code) = dc_obj.get_claim_info(ro_json)
            if claim_resp.get('ApiError'):
                result['msg'] += claim_resp['ApiError']
                return_code = 1
                logging.info(json.dumps(result))


            result['msg'] += "  Id: %s" % device_id
            result['msg'] += "  Token: %s" % claim_code
            logging.info(result)

            request_body = {
                "SecurityToken": claim_code,
                "SerialNumber": device_id
            }

        return request_body

    except requests.exceptions.ConnectionError as con_err:
        exception_print(
            con_err,
            "Exception retreiving claim information from device: " +
            device['hostname']
        )
        sys.exit(1)
    except Exception as con_err:
        exception_print(
            con_err,
            "Exception retreiving claim information from device: " +
            device['hostname']
        )
        sys.exit(1)

    finally:
        # logout of any sessions active after exception handling
        if ('dc_obj' in locals() or 'dc_obj' in globals()):
            dc_obj.logout()

def set_intersight_auth(CLAIM_CONFIG):
    """ Setup Intersight Auth Object """

    return IntersightAuth(
        secret_key_filename=CLAIM_CONFIG['intersight_authentication']['secret_key_filename'],
        api_key_id=CLAIM_CONFIG['intersight_authentication']['api_key_id']
    )

def claim_intersight_device(AUTH, CLAIM_CODES, CLAIM_CONFIG):
    """ Claim Device to Intersight """

    response = requests.post(
        CLAIM_CONFIG['intersight_base_url'] + 'asset/DeviceClaims',
        data=json.dumps(CLAIM_CODES),
        auth=AUTH
    )
    logging.info(response.text)

    response_json = response.json()
    logging.info(response_json["Device"]["Moid"])

    return response_json["Device"]["Moid"]

def add_intersight_resource_group(AUTH, MOIDS, CLAIM_CONFIG):
    """ Create an Intersight Resource Group for Claimed Devices """

    request_body = {
        "Name":CLAIM_CONFIG['partner_id'] + "-rg",
        "Qualifier":"Allow-Selectors",
        "Selectors":[
            {
                "Selector": (
                    "/api/v1/asset/DeviceRegistrations?$filter=Moid in('" +
                    ",".join(MOIDS) + "')"
                )
            }
        ]
    }
    logging.info(request_body)

    response = requests.post(
        CLAIM_CONFIG['intersight_base_url'] + 'resource/Groups',
        data=json.dumps(request_body),
        auth=AUTH
    )
    logging.info(response.text)

    response_json = response.json()
    logging.info("RESOURCE GROUP: " + response_json["Moid"])

    return response_json["Moid"]

def add_intersight_org(AUTH, RES_MOID, CLAIM_CONFIG):
    """ Add Intersight Organization """

    request_body = {
        "Name": CLAIM_CONFIG['partner_id'],
        "Description": "Org for " + CLAIM_CONFIG['partner_id'],
        "ResourceGroups": [
            {
                "ObjectType":"resource.Group",
                "Moid":RES_MOID
            }
        ]
    }
    logging.info(request_body)

    response = requests.post(
        CLAIM_CONFIG['intersight_base_url'] + 'organization/Organizations',
        data=json.dumps(request_body),
        auth=AUTH
    )
    logging.info(response.text)

    response_json = response.json()
    logging.info("ORGANIZATION: " + response_json["Moid"])

    return response_json["Moid"]

def add_intersight_role(AUTH, CLAIM_CONFIG):
    """ Create Intersight Role """

    request_body = {
        "Name": CLAIM_CONFIG['partner_id']
    }
    logging.info(request_body)

    response = requests.post(
        CLAIM_CONFIG['intersight_base_url'] + 'iam/Permissions',
        data=json.dumps(request_body),
        auth=AUTH
    )
    logging.info(response.text)

    response_json = response.json()
    logging.info("ROLE: " + response_json["Moid"])

    return response_json["Moid"]

def update_intersight_role(AUTH, ORG_MOID, ROLE_MOID, CLAIM_CONFIG):
    """ Add priviledges to an Intersight Role """

    response = requests.get(
        CLAIM_CONFIG['intersight_base_url'] +
        "iam/Roles?$select=Name,Moid&$filter=Name%20in%20%28" + 
        ",".join(CLAIM_CONFIG['intersight_roles']) + "%29",
        auth=AUTH
    )
    logging.info("ROLE MOIDS :" + response.text)
    response_json = response.json()

    request_roles = []
    for role_moid_dict in response_json["Results"]:
        logging.info(role_moid_dict["Moid"])
        request_roles.append({
            "ObjectType":"iam.Role",
            "Moid":role_moid_dict["Moid"]
        })

    logging.info(request_roles)
    request_body = {
        "Permission":{
            "ObjectType":"iam.Permission",
            "Moid": ROLE_MOID
        },
        "Resource":{
            "ObjectType":"organization.Organization",
            "Moid": ORG_MOID
        },"Roles":request_roles
    }
    logging.info(request_body)

    response = requests.post(
        CLAIM_CONFIG['intersight_base_url'] + 'iam/ResourceRoles',
        data=json.dumps(request_body),
        auth=AUTH
    )
    logging.info(response.text)

    response_json = response.json()
    return response_json["Moid"]

if __name__ == "__main__":

    # Device MOIDs
    MOIDS = []

    # Read in Claim Configuration
    CLAIM_CONFIG = get_claim_config()
    logging.info(CLAIM_CONFIG)

    # Create Intersight Autorization Object
    AUTH = set_intersight_auth(CLAIM_CONFIG)

    # Claim Devices
    for device in CLAIM_CONFIG['devices']:
        CLAIM_CODES = get_device_claim_codes(device)
        logging.info(CLAIM_CODES)

        MOIDS.append(
            claim_intersight_device(
                AUTH, CLAIM_CODES, CLAIM_CONFIG
            )
        )
    logging.info(MOIDS)

    # Create Intersight Reasource Group with Claimed Devices
    RES_MOID = add_intersight_resource_group(AUTH, MOIDS, CLAIM_CONFIG)

    # Create Intersight Organization using Resource Group
    ORG_MOID = add_intersight_org(AUTH, RES_MOID, CLAIM_CONFIG)

    # Create Intersight Role
    ROLE_MOID = add_intersight_role(AUTH, CLAIM_CONFIG)

    update_intersight_role(AUTH, ORG_MOID, ROLE_MOID, CLAIM_CONFIG)
