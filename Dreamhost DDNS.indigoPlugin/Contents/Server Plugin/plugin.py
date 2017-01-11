#! /usr/bin/env python
# -*- coding: utf-8 -*-
###############################################################################
#
#       Adapted from 'dreampy-dns':
#   
#       https://github.com/gsiametis/dreampy_dns
#
#       (not tested with ipv6)
#
###############################################################################
# Copyright (c) 2014, Perceptive Automation, LLC. All rights reserved.
# http://www.indigodomo.com

import indigo
import time
import re
import socket
import httplib
import ssl
import uuid

# Note the "indigo" module is automatically imported and made available inside
# our global name space by the host process.

###############################################################################
# globals

API_url = "api.dreamhost.com"


################################################################################
class Plugin(indigo.PluginBase):
    ########################################
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
    
    def __del__(self):
        indigo.PluginBase.__del__(self)

    ########################################
    # Start and Stop
    ########################################
    def startup(self):
        self.debug = self.pluginPrefs.get("showDebugInfo",False)
        self.logger.debug("startup")
        if self.debug:
            self.logger.debug("Debug logging enabled")
        
    ########################################
    def shutdown(self):
        self.logger.debug("shutdown")
        self.pluginPrefs['showDebugInfo'] = self.debug
    
    ########################################
    # Config and Validate
    ########################################
    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        self.logger.debug("closedPrefsConfigUi")
        if not userCancelled:
            self.debug = valuesDict.get("showDebugInfo",False)
            if self.debug:
                self.logger.debug("Debug logging enabled")

    ########################################
    def validatePrefsConfigUi(self, valuesDict):
        self.logger.debug("validatePrefsConfigUi")
        errorsDict = indigo.Dict()
        
        if not valuesDict.get('apiKey',""):
            errorsDict['apiKey'] = "Required"
        
        if len(errorsDict) > 0:
            return (False, valuesDict, errorsDict)
        return (True, valuesDict)
    
    
    ########################################
    # Action Methods
    ########################################
    def validateActionConfigUi(self, valuesDict, typeId, devId):
        self.logger.debug("validateActionConfigUi: " + typeId)
        errorsDict = indigo.Dict()
        
        if not is_valid_hostname(valuesDict.get('domain',"")):
            errorsDict['domain'] = "Not a valid hostname"
        if valuesDict.get('sourceType') == "device":
            if not valuesDict.get('sourceDevice',""):
                errorsDict['sourceDevice'] = "Required"
            if not valuesDict.get('sourceState',""):
                errorsDict['sourceState'] = "Required"
        elif valuesDict.get('sourceType') == "variable":
            if not valuesDict.get('sourceVariable',""):
                errorsDict['sourceVariable'] = "Required"
        
        if len(errorsDict) > 0:
            return (False, valuesDict, errorsDict)
        return (True, valuesDict)
    
    ########################################
    def updateDDNS(self, action):
        self.logger.debug("updateDDNS: "+action.props['domain'])
        startTime = time.time()
        
        if action.props['sourceType'] == "device":
            devId = int(action.props['sourceDevice'])
            state = action.props['sourceState']
            ipAddress = indigo.devices[devId].states[state]
        elif action.props['sourceType'] == "variable":
            varId = int(action.props['sourceVariable'])
            ipAddress = indigo.variables[varId].value
        
        if is_valid_ipv4_address(ipAddress):
            rec_type = 'A'
        elif is_valid_ipv6_address(ipAddress):
            rec_type = 'AAAA'
        else:
            self.logger.error("'%s' is not a valid IP Address" % ipAddress)
            return
        
        domain = action.props['domain']
        key = self.pluginPrefs['apiKey']
        current_records = get_dns_records(domain, key)
        current_dns_ip  = get_dns_ip(current_records, rec_type)
        self.logger.debug("current DNS IP: "+current_dns_ip)
        if current_dns_ip == ipAddress:
            self.logger.info("DNS for '%s' is current" % domain)
        else:
            self.logger.info("DNS for '%s' not current" % domain)
            if current_dns_ip:
                result, response = del_dns_record(domain, key, current_dns_ip, rec_type)
                if not result: 
                    self.logger.error("del_dns_record: "+response)
            result, response = add_dns_record(domain, key, ipAddress, rec_type)
            if result: 
                self.logger.info("DNS for '%s' updated to '%s'" % (domain, ipAddress))
            else: 
                self.logger.error("add_dns_record: "+response)

        self.logger.debug("updateDDNS: %s seconds" % (time.time()-startTime) )

    ########################################
    # Menu Methods
    ########################################
    def toggleDebug(self):
        if self.debug:
            self.logger.debug("Debug logging disabled")
            self.debug = False
        else:
            self.debug = True
            self.logger.debug("Debug logging enabled")
    
    ########################################
    # Menu Callbacks
    ########################################
    def formFieldChanged(self, filter="", valuesDict=None, typeId="", targetId=0):
        return
    
    ########################################
    def getStateList(self, filter="", valuesDict=None, typeId="", targetId=0):
        devId = int(valuesDict.get('sourceDevice',"0"))
        if devId:
            listArray = []
            for state in indigo.devices[devId].states:
                listArray.append((state,state))
            return listArray
        else:
            return []
    
########################################
# Utilities
########################################
def dreamhost_command(command, key):
    substring = "/?key=" + key + "&cmd=" +command + "&unique_id=" + str(uuid.uuid4())
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    conn = httplib.HTTPSConnection(API_url, 443, context=context)
    conn.request("GET", substring)
    body = conn.getresponse().read().decode('UTF-8')
    return body

def get_dns_records(domain, key):
    response = dreamhost_command("dns-list_records", key)
    relevant_records = []
    for line in response.splitlines():
        if domain in line:
            relevant_records.append(line)
    return relevant_records
    
def get_dns_ip(records, rec_type='A'):
    for line in records:
        values = line.expandtabs().split()
        if values[3]==rec_type:
            return values[-2]
    return ""

def del_dns_record(domain, key, value, rec_type='A'):
    command = "dns-remove_record&record=" + domain + "&type=" + rec_type + "&value=" + value
    response = dreamhost_command(command, key)
    if 'error' in response:
        return False, response
    else:
        return True, response

def add_dns_record(domain, key, value, rec_type='A'):
    command = "dns-add_record&record=" + domain + "&type=" + rec_type + "&value=" + value
    response = dreamhost_command(command, key)
    if 'error' in response:
        return False, response
    else:
        return True, response


# http://stackoverflow.com/questions/2532053/validate-a-hostname-string
def is_valid_hostname(hostname):
    if not hostname: return False
    if not isinstance(hostname, (str, unicode)): return False
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

# http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
    if not address: return False
    if not isinstance(address, (str, unicode)): return False
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True
def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

