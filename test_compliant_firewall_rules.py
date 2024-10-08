import pytest
import aiohttp
from compliant_firewall_rules import check_if_direction_is_ingress, check_ports, check_ip_addresses, get_firewall_rules, PORTS

def test_check_if_direction_is_not_ingress():
    rule = [
        {
            "RuleId": "102",
            "Direction": "Egress",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": ["236.216.246.119"],
            "Action": "Allow"
        }
    ]
    
    expected_output = [
        {"RuleId": "102", "Compliance": "COMPLIANT"}
    ]
    assert check_if_direction_is_ingress(rule) == expected_output
    
def test_check_if_direction_is_ingress():
    rule = [
        {
            "RuleId": "100",
            "Direction": "Ingress",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": ["236.216.246.119"],
            "Action": "Deny"
        }
    ]
    
    expected_output = [
        {"RuleId": "100", "Compliance": "COMPLIANT"}
    ]
    
    assert check_if_direction_is_ingress(rule) == expected_output
    
def test_check_if_relevant_ports_are_compliant():
  for port in PORTS:
    rules = {
            "RuleId": "200",
            "Direction": "Ingress",
            "FromPort": port,
            "ToPort": 49151,
            "IpRanges": ["236.216.246.119"],
            "Action": "Deny" 
            }
    expected_output = {"RuleId": "200", "Compliance": "COMPLIANT"}
    assert check_ports(rules) == expected_output
    
def test_check_if_irrelevant_ports_are_compliant():
  rule = {
          "RuleId": "200",
          "Direction": "Ingress",
          "FromPort": 10,
          "ToPort": 20,
          "IpRanges": ["236.216.246.119"],
          "Action": "Allow" 
          }
  expected_output = {"RuleId": "200", "Compliance": "COMPLIANT"}
  assert check_ports(rule) == expected_output
  
def test_check_if_ip_in_range_is_compliant():
  rule = {
          "RuleId": "200",
          "Direction": "Ingress",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": ["236.216.246.119/32",
                       "78.76.115.63/14",
                      "114.131.46.115/30",
                      "221.98.94.123/22"],
          "Action": "Deny" 
          }
  expected_output = {"RuleId": "200", "Compliance": "COMPLIANT"}
  assert check_ip_addresses(rule) == expected_output
  
def test_check_if_ip_in_range_is_not_compliant():
  rule = {
          "RuleId": "200",
          "Direction": "Ingress",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": ["236.216.246.119/32",
                       "78.76.115.63/14",
                      "114.131.46.115/30",
                      "221.98.94.123/22"],
          "Action": "Allow" 
          }
  expected_output = {"RuleId": "200", "Compliance": "NON_COMPLIANT"}
  assert check_ip_addresses(rule) == expected_output
  
@pytest.mark.asyncio
async def test_http_error_code(monkeypatch):
    monkeypatch.setattr('compliant_firewall_rules.FIREWALL_RULES_ENDPOINT', 'https://httpbin.org/status/500')
    
    with pytest.raises(aiohttp.ClientError):
        await get_firewall_rules()