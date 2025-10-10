#!/usr/bin/env python
import os
import sys
import django

sys.path.insert(0, '/opt/netbox/netbox')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netbox.settings')
django.setup()

from django.core.exceptions import ValidationError
from netbox_netbox_auto_discovery_plugin.models import Scanner
from netbox_netbox_auto_discovery_plugin.choices import ScannerTypeChoices, ConnectionProtocolChoices

def test_validation(description, test_func):
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print('='*60)
    try:
        test_func()
        print("❌ FAILED: Expected validation error but none was raised")
        return False
    except ValidationError as e:
        print(f"✅ PASSED: Validation error raised as expected")
        print(f"   Error: {e.message_dict if hasattr(e, 'message_dict') else e}")
        return True
    except Exception as e:
        print(f"❌ FAILED: Unexpected error: {type(e).__name__}: {e}")
        return False

def test_valid_scanner():
    print(f"\n{'='*60}")
    print(f"TEST: Valid network range scanner")
    print('='*60)
    try:
        scanner = Scanner(
            name="Valid Scanner",
            scanner_type=ScannerTypeChoices.TYPE_NETWORK_RANGE,
            cidr_range="192.168.1.0/24"
        )
        scanner.full_clean()
        print("✅ PASSED: Valid scanner accepted")
        scanner.delete() if scanner.pk else None
        return True
    except ValidationError as e:
        print(f"❌ FAILED: Valid scanner rejected")
        print(f"   Error: {e.message_dict if hasattr(e, 'message_dict') else e}")
        return False

def run_tests():
    print("\n" + "="*60)
    print("VALIDATION TEST SUITE")
    print("="*60)
    
    results = []
    
    results.append(test_validation(
        "Empty CIDR for network range scanner",
        lambda: Scanner(
            name="Test1",
            scanner_type=ScannerTypeChoices.TYPE_NETWORK_RANGE,
            cidr_range=""
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Invalid CIDR format",
        lambda: Scanner(
            name="Test2",
            scanner_type=ScannerTypeChoices.TYPE_NETWORK_RANGE,
            cidr_range="not-a-cidr"
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Invalid CIDR notation",
        lambda: Scanner(
            name="Test3",
            scanner_type=ScannerTypeChoices.TYPE_NETWORK_RANGE,
            cidr_range="999.999.999.999/24"
        ).full_clean()
    ))
    
    results.append(test_validation(
        "CIDR range too large",
        lambda: Scanner(
            name="Test4",
            scanner_type=ScannerTypeChoices.TYPE_NETWORK_RANGE,
            cidr_range="10.0.0.0/4"
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Empty target hostname for Cisco scanner",
        lambda: Scanner(
            name="Test5",
            scanner_type=ScannerTypeChoices.TYPE_CISCO_SWITCH,
            target_hostname=""
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Invalid target hostname",
        lambda: Scanner(
            name="Test6",
            scanner_type=ScannerTypeChoices.TYPE_CISCO_SWITCH,
            target_hostname="invalid!@#$%"
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Missing SSH username",
        lambda: Scanner(
            name="Test7",
            scanner_type=ScannerTypeChoices.TYPE_CISCO_SWITCH,
            target_hostname="192.168.1.1",
            connection_protocol=ConnectionProtocolChoices.PROTOCOL_SSH,
            ssh_username="",
            ssh_password="password123"
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Missing SSH password",
        lambda: Scanner(
            name="Test8",
            scanner_type=ScannerTypeChoices.TYPE_CISCO_SWITCH,
            target_hostname="192.168.1.1",
            connection_protocol=ConnectionProtocolChoices.PROTOCOL_SSH,
            ssh_username="admin",
            ssh_password=""
        ).full_clean()
    ))
    
    results.append(test_validation(
        "Missing SNMP community for v2c",
        lambda: Scanner(
            name="Test9",
            scanner_type=ScannerTypeChoices.TYPE_CISCO_SWITCH,
            target_hostname="192.168.1.1",
            connection_protocol=ConnectionProtocolChoices.PROTOCOL_SNMP_V2C,
            snmp_community=""
        ).full_clean()
    ))
    
    results.append(test_valid_scanner())
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED")
        return 1

if __name__ == '__main__':
    sys.exit(run_tests())
