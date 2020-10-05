#!/usr/bin/env python
"""Intersight Device Connector API access classes."""
import re
from xml.etree import ElementTree
from time import sleep
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def requests_op(op, uri, header, ro_json, body):
    """perform op and retry on 5XX status errors"""
    for _ in range(10):
        if op == 'GET':
            resp = requests.get(uri, verify=False, headers=header)
        elif op == 'PUT':
            resp = requests.put(uri, verify=False, headers=header, json=body)
        else:
            ro_json['ApiError'] = "unsupported op %s" % (op)
            break

        if re.match(r'2..', str(resp.status_code)):
            ro_json.pop('ApiError', None)
            if op == 'GET':
                if isinstance(resp.json(), list):
                    ro_json = resp.json()[0]
                else:
                    ro_json['ApiError'] = "%s %s %s" % (op, uri, resp.status_code)
            break
        else:
            ro_json['ApiError'] = "%s %s %s" % (op, uri, resp.status_code)
            if re.match(r'5..', str(resp.status_code)):
                sleep(1)
                continue
            else:
                break
    return ro_json


class DeviceConnector():
    """Intersight Device Connector API superclass.
    Managed endpoint access information (hostname, username) and configuration data should be provided in the device dictionary parameter.
    """
    def __init__(self, device):
        self.logged_in = False
        self.auth_header = ''
        self.device = device
        self.connector_uri = "https://%s/connector" % self.device['hostname']
        self.systems_uri = "%s/Systems" % self.connector_uri

    def get_status(self):
        """Check current connection status."""
        ro_json = dict(AdminState=False)
        # get admin, connection, and claim state
        ro_json = requests_op(op='GET', uri=self.systems_uri, header=self.auth_header, ro_json=ro_json, body={})
        return ro_json

    def configure_connector(self):
        """Check current Admin state and enable the Device Connector if not currently enabled."""
        ro_json = dict(AdminState=False)
        for _ in range(4):
            ro_json = self.get_status()
            if ro_json['AdminState']:
                break
            else:
                # enable the device connector
                ro_json = requests_op(op='PUT', uri=self.systems_uri, header=self.auth_header, ro_json=ro_json, body={'AdminState': True})
                if ro_json.get('ApiError'):
                    break
        return ro_json

    def configure_access_mode(self, ro_json):
        """Configure the Device Connector access mode (ReadOnlyMode True/False)."""
        for _ in range(4):
            # device read_only setting is a bool (True/False)
            ro_json = requests_op(op='PUT', uri=self.systems_uri, header=self.auth_header, ro_json=ro_json, body={'ReadOnlyMode': self.device['read_only']})
            if ro_json.get('ApiError'):
                break
            # confirm setting has been applied
            ro_json = self.get_status()
            if ro_json['ReadOnlyMode'] == self.device['read_only']:
                break
        return ro_json

    def get_claim_info(self, ro_json):
        """Get the Device ID and Claim Code from the Device Connector."""
        claim_resp = {}
        device_id = ''
        claim_code = ''
        # get device id and claim code
        id_uri = "%s/DeviceIdentifiers" % self.connector_uri
        ro_json = requests_op(op='GET', uri=id_uri, header=self.auth_header, ro_json=ro_json, body={})
        print(ro_json)
        if not ro_json.get('ApiError'):
            device_id = ro_json['Id']

            claim_uri = "%s/SecurityTokens" % self.connector_uri
            ro_json = requests_op(op='GET', uri=claim_uri, header=self.auth_header, ro_json=ro_json, body={})
            print(ro_json)
            if not ro_json.get('ApiError'):
                claim_code = ro_json['Token']
            else:
                claim_resp['ApiError'] = ro_json['ApiError']
        else:
            claim_resp['ApiError'] = ro_json['ApiError']
        return(claim_resp, device_id, claim_code)

class UcsDeviceConnector(DeviceConnector):
    """UCS Manager (UCSM) Device Connector subclass.
    UCS XML API session cookie is used to authenticate Device Connector API access.
    """
    def __init__(self, device):
        super(UcsDeviceConnector, self).__init__(device)
        # XML API login and create session cookie
        # --------------------------------
        self.xml_uri = "https://%s/nuova" % self.device['hostname']
        xml_body = "<aaaLogin inName='%s' inPassword='%s' />" % (self.device['username'], self.device['password'])
        resp = requests.post(self.xml_uri, verify=False, data=xml_body, timeout=5)
        print(resp.text)
        if re.match(r'2..', str(resp.status_code)):
            xml_tree = ElementTree.fromstring(resp.content)
            if not xml_tree.attrib.get('outCookie'):
                return
            self.xml_cookie = xml_tree.attrib['outCookie']
            self.auth_header = {'ucsmcookie': "ucsm-cookie=%s" % self.xml_cookie}
            self.logged_in = True
            print(self.xml_cookie, self.auth_header, self.logged_in)

    def logout(self):
        """Logout of UCSM API session if currently logged in."""
        if self.logged_in:
            # XML API logout
            # --------------------------------
            xml_body = "<aaaLogout inCookie='%s' />" % self.xml_cookie
            resp = requests.post(self.xml_uri, verify=False, data=xml_body)
            print(resp.text)
            self.logged_in = False

if __name__ == "__main__":
    pass