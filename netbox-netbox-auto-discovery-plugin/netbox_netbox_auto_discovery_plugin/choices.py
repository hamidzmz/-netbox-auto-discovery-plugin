from utilities.choices import ChoiceSet


class ScannerTypeChoices(ChoiceSet):

    TYPE_NETWORK_RANGE = 'network_range'
    TYPE_CISCO_SWITCH = 'cisco_switch'

    CHOICES = [
        (TYPE_NETWORK_RANGE, 'Network Range Scan', 'green'),
        (TYPE_CISCO_SWITCH, 'Cisco Switch Scan', 'blue'),
    ]


class ScannerStatusChoices(ChoiceSet):

    STATUS_ACTIVE = 'active'
    STATUS_DISABLED = 'disabled'

    CHOICES = [
        (STATUS_ACTIVE, 'Active', 'green'),
        (STATUS_DISABLED, 'Disabled', 'gray'),
    ]


class ScanRunStatusChoices(ChoiceSet):

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'

    CHOICES = [
        (STATUS_PENDING, 'Pending', 'gray'),
        (STATUS_RUNNING, 'Running', 'blue'),
        (STATUS_COMPLETED, 'Completed', 'green'),
        (STATUS_FAILED, 'Failed', 'red'),
        (STATUS_CANCELLED, 'Cancelled', 'orange'),
    ]


class ConnectionProtocolChoices(ChoiceSet):

    PROTOCOL_SSH = 'ssh'
    PROTOCOL_SNMP_V2C = 'snmp_v2c'
    PROTOCOL_SNMP_V3 = 'snmp_v3'

    CHOICES = [
        (PROTOCOL_SSH, 'SSH', 'blue'),
        (PROTOCOL_SNMP_V2C, 'SNMP v2c', 'green'),
        (PROTOCOL_SNMP_V3, 'SNMP v3', 'cyan'),
    ]
