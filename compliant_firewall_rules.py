import asyncio #async operations
import aiohttp #async http requests
import json #handle json data and json parsing
import ipaddress #handle ip addresses/networks
""""
Compliance requirement: Firewall rules shall NOT allow ingress(Inbound) traffic on port 22, 80, or 443 from the following IP addresses:
236.216.246.119
109.3.194.189
36.229.68.87
21.90.154.237
91.172.88.105
"""
PORTS = [22,80,443, -1] #Ports of interest for ingress rules, -1 means every port.
IPADDRESSES = set([ipaddress.IPv4Address("236.216.246.119"), #List of Ip's that should NOT allow ingress trafic on ports from the PORTS array.
            ipaddress.IPv4Address("109.3.194.189"), #Sets are generally faster.
            ipaddress.IPv4Address("36.229.68.87"),  
            ipaddress.IPv4Address("21.90.154.237"),
            ipaddress.IPv4Address("91.172.88.105")])

FIREWALLRULESENDPOINT = "https://g326av89lk.execute-api.us-east-1.amazonaws.com/prod/rules" #Endpoint with firewall rules
             
async def get_firewall_rules(pagination=None):
    """
    Fetches the firewall rules from the endpoint
    
    Args:
        pagination: A dictionary containing pagination information for fetching the next set of results. Defaults to None.
    """
    async with aiohttp.ClientSession() as session:
        try:
            results = []
            
            if pagination is None:
                async with session.get(FIREWALLRULESENDPOINT) as response: #Get request to url
                    response.raise_for_status()  # Raise error for any HTTP related issues
                    data = await response.json()  # Await the JSON response
                    results += check_if_direction_is_ingress(data['Items'])
            else:
                last_evaluated_key = json.dumps(pagination) #The pagination portion of the url needs to be in json format
                async with session.get(f"{FIREWALLRULESENDPOINT}?ExclusiveStartKey={last_evaluated_key}") as response: #Append the pagination to url
                    response.raise_for_status()  
                    data = await response.json()
                    results += check_if_direction_is_ingress(data['Items'])

            if 'LastEvaluatedKey' in data: #If the value LastEvaluatedKey exists in the JSON response. We are still not in the last page
                lastEvaluatedKey = data['LastEvaluatedKey']
                results += await get_firewall_rules(lastEvaluatedKey) #Recursively fetch the next page 
                
            return results
        except aiohttp.ClientError as e: #Any HTTP errors
            print(f"HTTP error: {e}")
        except Exception as e: #Any other type of errors
            print(f"Unexpected error: {e}")
            
def check_if_direction_is_ingress(items):
    """
    Checks if the rules from the current page are related to ingress. Since the compliance requirement 
    is only for the ingress direction, any other direction will default to 'NON_COMPLIANT' an no other check will be done.
    
    Args:
        items: A dictionary containing the rules from the current page
    """
    results = []
    for rule in items: #Loop every rule in the page
        if rule['Direction'] == 'Ingress': #If the direction is Ingress, this rule is of interest and we will proceed to look at the ports
            results.append(check_ports(rule))
        else:
            results.append({"RuleId": rule['RuleId'],  # None Ingress direction, mark as NON_COMPLIANT
                            "Compliance": "NON_COMPLIANT"})
    return results
            
def check_ports(rule):
    """
    Checks if the current rule is using any ports of interests for the compliance requirement
    
    Args:
        rule: a single rule dictionary
    """
    # Loop the PORTS array and check if the current port range contains any of the ports in PORTS, if so, check the rule. 
    for port in PORTS:
        if rule['FromPort'] <= port <= rule['ToPort']:
            return check_ip_addresses(rule)
    
    # If none of the sensitive ports are in the range, NON_COMPLIANT
    return {"RuleId": rule['RuleId'],  
            "Compliance": "NON_COMPLIANT"}
        
def check_ip_addresses(rule):
    """
    Checks the list of IP's of the current rule.
    
    Args:
        rule: a single rule dictionary
    """
    networks = set() #networks will contain a set of all of the ips in the IPv4 CIDR range.
    for ip_network in rule['IpRanges']: # Navigate the list of IPs in the current rule
        try:
            networks.add(ipaddress.IPv4Network(ip_network, strict=False)) # Each network from the rule list will be stored as an IPv4Network object
        except ValueError as e:
            print(f"Skipping invalid network '{ip_network}': {e}")
    
    for network in networks: #For every network in the CIDR range
        for ip in IPADDRESSES: #For every IP in the IPADDRESSES set
            if ip in network: #Does the current IPADDRESSES exist in the subnet of the current network iteration?
                if rule['Action'] == 'Deny':  # If it exists and the action is 'Deny', the rule is COMPLIANT
                    return {"RuleId": rule['RuleId'],
                            "Compliance": "COMPLIANT"}
    # If no IP from IPADDRESSES is found in the network or the action is not 'Deny'
    return {"RuleId": rule['RuleId'],
            "Compliance": "NON_COMPLIANT"}
            
async def main():
    results = await get_firewall_rules()
    with open('Compliance.json', 'w') as file:
        json.dump(results, file, indent=4)  # indent is for pretty-print
    
asyncio.run(main())