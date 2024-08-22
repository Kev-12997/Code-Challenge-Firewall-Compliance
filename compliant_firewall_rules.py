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
IP_ADDRESSES = set([ipaddress.IPv4Address("236.216.246.119"), #List of Ip's that should NOT allow ingress trafic on ports from the PORTS array.
            ipaddress.IPv4Address("109.3.194.189"), #Sets are generally faster.
            ipaddress.IPv4Address("36.229.68.87"),  
            ipaddress.IPv4Address("21.90.154.237"),
            ipaddress.IPv4Address("91.172.88.105")])

FIREWALL_RULES_ENDPOINT = "https://g326av89lk.execute-api.us-east-1.amazonaws.com/prod/rules" #Endpoint with firewall rules
             
async def get_firewall_rules(pagination=None):
    """
    Fetches the firewall rules from the endpoint
    
    Args:
        pagination: A dictionary containing pagination information for fetching the next set of results. Defaults to None.
    """
    async with aiohttp.ClientSession() as session:
        results = [] #Array that will contain the json array object of the final output
        current_pagination = pagination #Tracks current page
        
        try:
            while True: #Will remain true as long as the current page has a LastEvaluatedKey value
            
                if current_pagination is None: 
                    url = FIREWALL_RULES_ENDPOINT
                else:
                    last_evaluated_key = json.dumps(current_pagination)
                    url = f"{FIREWALL_RULES_ENDPOINT}?ExclusiveStartKey={last_evaluated_key}"

                async with session.get(url) as response:
                    response.raise_for_status() # Raise error for any HTTP related issues
                    data = await response.json() # Await the JSON response

                results.extend(check_if_direction_is_ingress(data['Items']))

                if 'LastEvaluatedKey' not in data:
                    break #Break out of while loop when reaching the last page

                current_pagination = data['LastEvaluatedKey']
                
        except aiohttp.ClientError as e: #Any HTTP errors
            print(f"HTTP error: {e}")
            raise
        except Exception as e: #Any other type of errors
            print(f"Unexpected error: {e}")
                
        return results
            
def check_if_direction_is_ingress(items):
    """
    Checks if the rules from the current page are related to ingress. Since the compliance requirement 
    is only for the ingress direction, any other direction will default to 'COMPLIANT' an no other check will be done.
    
    Args:
        items: A dictionary containing the rules from the current page
    """
    results = []
    for rule in items: #Loop every rule in the page
        if rule['Direction'] == 'Ingress': #If the direction is Ingress, this rule is of interest and we will proceed to look at the ports
            results.append(check_ports(rule))
        else:
            results.append(compliant_rule(rule))  # None Ingress direction, mark as COMPLIANT
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
    
    # If none of the sensitive ports are in the range, COMPLIANT
    return compliant_rule(rule)
        
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
        for ip in IP_ADDRESSES: #For every IP in the IPADDRESSES set
            if ip in network: #Does the current IPADDRESSES exist in the subnet of the current network iteration?
                if rule['Action'] == 'Deny':  # If it exists and the action is 'Deny', the rule is COMPLIANT
                    return compliant_rule(rule)
                else: # Only rules that are non compliant are rules that DO allow trafic over the sensitive ports on the specified IPs
                    return {"RuleId": rule['RuleId'],
                            "Compliance": "NON_COMPLIANT"}
                    
    # If no IP from IPADDRESSES is found in the network
    return compliant_rule(rule)

"""
Returns the COMPLIANT json
"""
def compliant_rule(rule):
    return {"RuleId": rule['RuleId'],
            "Compliance": "COMPLIANT"}
            
async def main():
    results = await get_firewall_rules()
    with open('Compliance.json', 'w') as file:
        json.dump(results, file, indent=4)  # indent is for pretty-print
    
asyncio.run(main())