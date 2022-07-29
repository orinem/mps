/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

export const amtPort = 16992

export const DefaultNetworkingAdaptor = 'eth0'

export const UUIDRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

// HTTP error codes
export const httpErrorTable = {
  200: 'OK',
  400: 'Incorrect URI or Bad Request',
  401: 'Authentication Error',
  404: {
    alarm: 'Alarm instance not found',
    device: 'Device not found/connected. Please connect again using CIRA.',
    method: 'Request does not contain method',
    noMethod: 'Requested method does not exists',
    payload: 'Request does not contain payload',
    guid: 'GUID does not exist in the payload',
    action: 'Power action type does not exist',
    invalidGuid: 'GUID empty/invalid'
  },
  408: 'Timeout Error',
  500: 'Internal Server Error',
  601: 'WSMAN Parsing Error',
  602: 'Unable to parse HTTP response header',
  603: 'Unexpected HTTP enum response',
  604: 'Unexpected HTTP pull response'
}

// Power Actions supported as per Distributed Management Task Force standard.
// ValueMap={2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
// Values={Power On, Sleep - Light, Sleep - Deep, Power Cycle (Off Soft), Power Off - Hard, Hibernate, Power Off - Soft, Power Cycle (Off Hard), Master Bus Reset, Diagnostic Interrupt (NMI), Power Off - Soft Graceful, Power Off - Hard Graceful, Master Bus Reset Graceful, Power Cycle (Off - Soft Graceful), Power Cycle (Off - Hard Graceful)}
export const DMTFPowerStates = [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17]
export const DMTFPowerExtendedStates = [100, 101, 104, 200, 201, 202, 203, 300, 301, 400, 401]

export const UserConsentOptions = {
  none: 0,
  kvm: 1,
  all: 4294967295
}

export const AMTStatusCodes = {
  0x0000: 'SUCCESS',
  0x0001: 'INTERNAL_ERROR',
  0x0002: 'NOT_READY',
  0x0003: 'INVALID_PT_MODE',
  0x0004: 'INVALID_MESSAGE_LENGTH',
  0x0005: 'TABLE_FINGERPRINT_NOT_AVAILABLE',
  0x0006: 'INTEGRITY_CHECK_FAILED',
  0x0007: 'UNSUPPORTED_ISVS_VERSION',
  0x0008: 'APPLICATION_NOT_REGISTERED',
  0x0009: 'INVALID_REGISTRATION_DATA',
  0x000A: 'APPLICATION_DOES_NOT_EXIST',
  0x000B: 'NOT_ENOUGH_STORAGE',
  0x000C: 'INVALID_NAME',
  0x000D: 'BLOCK_DOES_NOT_EXIST',
  0x000E: 'INVALID_BYTE_OFFSET',
  0x000F: 'INVALID_BYTE_COUNT',
  0x0010: 'NOT_PERMITTED',
  0x0011: 'NOT_OWNER',
  0x0012: 'BLOCK_LOCKED_BY_OTHER',
  0x0013: 'BLOCK_NOT_LOCKED',
  0x0014: 'INVALID_GROUP_PERMISSIONS',
  0x0015: 'GROUP_DOES_NOT_EXIST',
  0x0016: 'INVALID_MEMBER_COUNT',
  0x0017: 'MAX_LIMIT_REACHED',
  0x0018: 'INVALID_AUTH_TYPE',
  0x0019: 'AUTHENTICATION_FAILED',
  0x001A: 'INVALID_DHCP_MODE',
  0x001B: 'INVALID_IP_ADDRESS',
  0x001C: 'INVALID_DOMAIN_NAME',
  0x001D: 'UNSUPPORTED_VERSION',
  0x001E: 'REQUEST_UNEXPECTED',
  0x001F: 'INVALID_TABLE_TYPE',
  0x0020: 'INVALID_PROVISIONING_STATE',
  0x0021: 'UNSUPPORTED_OBJECT',
  0x0022: 'INVALID_TIME',
  0x0023: 'INVALID_INDEX',
  0x0024: 'INVALID_PARAMETER',
  0x0025: 'INVALID_NETMASK',
  0x0026: 'FLASH_WRITE_LIMIT_EXCEEDED',
  0x0027: 'INVALID_IMAGE_LENGTH',
  0x0028: 'INVALID_IMAGE_SIGNATURE',
  0x0029: 'PROPOSE_ANOTHER_VERSION',
  0x002A: 'INVALID_PID_FORMAT',
  0x002B: 'INVALID_PPS_FORMAT',
  0x002C: 'BIST_COMMAND_BLOCKED',
  0x002D: 'CONNECTION_FAILED',
  0x002E: 'CONNECTION_TOO_MANY',
  0x002F: 'RNG_GENERATION_IN_PROGRESS',
  0x0030: 'RNG_NOT_READY',
  0x0031: 'CERTIFICATE_NOT_READY',
  0x0400: 'DISABLED_BY_POLICY',
  0x0800: 'NETWORK_IF_ERROR_BASE',
  0x0801: 'UNSUPPORTED_OEM_NUMBER',
  0x0802: 'UNSUPPORTED_BOOT_OPTION',
  0x0803: 'INVALID_COMMAND',
  0x0804: 'INVALID_SPECIAL_COMMAND',
  0x0805: 'INVALID_HANDLE',
  0x0806: 'INVALID_PASSWORD',
  0x0807: 'INVALID_REALM',
  0x0808: 'STORAGE_ACL_ENTRY_IN_USE',
  0x0809: 'DATA_MISSING',
  0x080A: 'DUPLICATE',
  0x080B: 'EVENTLOG_FROZEN',
  0x080C: 'PKI_MISSING_KEYS',
  0x080D: 'PKI_GENERATING_KEYS',
  0x080E: 'INVALID_KEY',
  0x080F: 'INVALID_CERT',
  0x0810: 'CERT_KEY_NOT_MATCH',
  0x0811: 'MAX_KERB_DOMAIN_REACHED',
  0x0812: 'UNSUPPORTED',
  0x0813: 'INVALID_PRIORITY',
  0x0814: 'NOT_FOUND',
  0x0815: 'INVALID_CREDENTIALS',
  0x0816: 'INVALID_PASSPHRASE',
  0x0818: 'NO_ASSOCIATION',
  0x081B: 'AUDIT_FAIL',
  0x081C: 'BLOCKING_COMPONENT',
  0x0821: 'USER_CONSENT_REQUIRED',
  0x1000: 'APP_INTERNAL_ERROR',
  0x1001: 'NOT_INITIALIZED',
  0x1002: 'LIB_VERSION_UNSUPPORTED',
  0x1003: 'INVALID_PARAM',
  0x1004: 'RESOURCES',
  0x1005: 'HARDWARE_ACCESS_ERROR',
  0x1006: 'REQUESTOR_NOT_REGISTERED',
  0x1007: 'NETWORK_ERROR',
  0x1008: 'PARAM_BUFFER_TOO_SHORT',
  0x1009: 'COM_NOT_INITIALIZED_IN_THREAD',
  0x100A: 'URL_REQUIRED'
}

// Default top and skip for api pagination

export const DEFAULT_TOP = 25
export const DEFAULT_SKIP = 0

export const SystemEntityTypes: {[key: number]: string} = {
  0: 'Unspecified',
  1: 'Other',
  2: 'Unknown',
  3: 'Processor',
  4: 'Disk',
  5: 'Peripheral',
  6: 'System management module',
  7: 'System board',
  8: 'Memory module',
  9: 'Processor module',
  10: 'Power supply',
  11: 'Add in card',
  12: 'Front panel board',
  13: 'Back panel board',
  14: 'Power system board',
  15: 'Drive backplane',
  16: 'System internal expansion board',
  17: 'Other system board',
  18: 'Processor board',
  19: 'Power unit',
  20: 'Power module',
  21: 'Power management board',
  22: 'Chassis back panel board',
  23: 'System chassis',
  24: 'Sub chassis',
  25: 'Other chassis board',
  26: 'Disk drive bay',
  27: 'Peripheral bay',
  28: 'Device bay',
  29: 'Fan cooling',
  30: 'Cooling unit',
  31: 'Cable interconnect',
  32: 'Memory device',
  33: 'System management software',
  34: 'BIOS',
  35: 'Intel(r) ME',
  36: 'System bus',
  37: 'Group',
  38: 'Intel(r) ME',
  39: 'External environment',
  40: 'Battery',
  41: 'Processing blade',
  42: 'Connectivity switch',
  43: 'Processor/memory module',
  44: 'I/O module',
  45: 'Processor I/O module',
  46: 'Management controller firmware',
  47: 'IPMI channel',
  48: 'PCI bus',
  49: 'PCI express bus',
  50: 'SCSI bus',
  51: 'SATA/SAS bus',
  52: 'Processor front side bus'
}

export const SystemFirmwareError: {[key: number]: string} = {
  0: 'Unspecified.',
  1: 'No system memory is physically installed in the system.',
  2: 'No usable system memory, all installed memory has experienced an unrecoverable failure.',
  3: 'Unrecoverable hard-disk/ATAPI/IDE device failure.',
  4: 'Unrecoverable system-board failure.',
  5: 'Unrecoverable diskette subsystem failure.',
  6: 'Unrecoverable hard-disk controller failure.',
  7: 'Unrecoverable PS/2 or USB keyboard failure.',
  8: 'Removable boot media not found.',
  9: 'Unrecoverable video controller failure.',
  10: 'No video device detected.',
  11: 'Firmware (BIOS) ROM corruption detected.',
  12: 'CPU voltage mismatch (processors that share same supply have mismatched voltage requirements)',
  13: 'CPU speed matching failure'
}

export const SystemFirmwareProgress: {[key: number]: string} = {
  0: 'Unspecified.',
  1: 'Memory initialization.',
  2: 'Starting hard-disk initialization and test',
  3: 'Secondary processor(s) initialization',
  4: 'User authentication',
  5: 'User-initiated system setup',
  6: 'USB resource configuration',
  7: 'PCI resource configuration',
  8: 'Option ROM initialization',
  9: 'Video initialization',
  10: 'Cache initialization',
  11: 'SM Bus initialization',
  12: 'Keyboard controller initialization',
  13: 'Embedded controller/management controller initialization',
  14: 'Docking station attachment',
  15: 'Enabling docking station',
  16: 'Docking station ejection',
  17: 'Disabling docking station',
  18: 'Calling operating system wake-up vector',
  19: 'Starting operating system boot process',
  20: 'Baseboard or motherboard initialization',
  21: 'reserved',
  22: 'Floppy initialization',
  23: 'Keyboard test',
  24: 'Pointing device test',
  25: 'Primary processor initialization'
}

export const WatchdogCurrentStates: {[key: number]: string} = {
  1: 'Not Started',
  2: 'Stopped',
  4: 'Running',
  8: 'Expired',
  16: 'Suspended'
}
export const AmtAuditStringTable = {
  16: 'Security Admin',
  17: 'RCO',
  18: 'Redirection Manager',
  19: 'Firmware Update Manager',
  20: 'Security Audit Log',
  21: 'Network Time',
  22: 'Network Administration',
  23: 'Storage Administration',
  24: 'Event Manager',
  25: 'Circuit Breaker Manager',
  26: 'Agent Presence Manager',
  27: 'Wireless Configuration',
  28: 'EAC',
  29: 'KVM',
  30: 'User Opt-In Events',
  32: 'Screen Blanking',
  33: 'Watchdog Events',
  1600: 'Provisioning Started',
  1601: 'Provisioning Completed',
  1602: 'ACL Entry Added',
  1603: 'ACL Entry Modified',
  1604: 'ACL Entry Removed',
  1605: 'ACL Access with Invalid Credentials',
  1606: 'ACL Entry State',
  1607: 'TLS State Changed',
  1608: 'TLS Server Certificate Set',
  1609: 'TLS Server Certificate Remove',
  1610: 'TLS Trusted Root Certificate Added',
  1611: 'TLS Trusted Root Certificate Removed',
  1612: 'TLS Preshared Key Set',
  1613: 'Kerberos Settings Modified',
  1614: 'Kerberos Master Key Modified',
  1615: 'Flash Wear out Counters Reset',
  1616: 'Power Package Modified',
  1617: 'Set Realm Authentication Mode',
  1618: 'Upgrade Client to Admin Control Mode',
  1619: 'Unprovisioning Started',
  1700: 'Performed Power Up',
  1701: 'Performed Power Down',
  1702: 'Performed Power Cycle',
  1703: 'Performed Reset',
  1704: 'Set Boot Options',
  1800: 'IDER Session Opened',
  1801: 'IDER Session Closed',
  1802: 'IDER Enabled',
  1803: 'IDER Disabled',
  1804: 'SoL Session Opened',
  1805: 'SoL Session Closed',
  1806: 'SoL Enabled',
  1807: 'SoL Disabled',
  1808: 'KVM Session Started',
  1809: 'KVM Session Ended',
  1810: 'KVM Enabled',
  1811: 'KVM Disabled',
  1812: 'VNC Password Failed 3 Times',
  1900: 'Firmware Updated',
  1901: 'Firmware Update Failed',
  2000: 'Security Audit Log Cleared',
  2001: 'Security Audit Policy Modified',
  2002: 'Security Audit Log Disabled',
  2003: 'Security Audit Log Enabled',
  2004: 'Security Audit Log Exported',
  2005: 'Security Audit Log Recovered',
  2100: 'Intel(R) ME Time Set',
  2200: 'TCPIP Parameters Set',
  2201: 'Host Name Set',
  2202: 'Domain Name Set',
  2203: 'VLAN Parameters Set',
  2204: 'Link Policy Set',
  2205: 'IPv6 Parameters Set',
  2300: 'Global Storage Attributes Set',
  2301: 'Storage EACL Modified',
  2302: 'Storage FPACL Modified',
  2303: 'Storage Write Operation',
  2400: 'Alert Subscribed',
  2401: 'Alert Unsubscribed',
  2402: 'Event Log Cleared',
  2403: 'Event Log Frozen',
  2500: 'CB Filter Added',
  2501: 'CB Filter Removed',
  2502: 'CB Policy Added',
  2503: 'CB Policy Removed',
  2504: 'CB Default Policy Set',
  2505: 'CB Heuristics Option Set',
  2506: 'CB Heuristics State Cleared',
  2600: 'Agent Watchdog Added',
  2601: 'Agent Watchdog Removed',
  2602: 'Agent Watchdog Action Set',
  2700: 'Wireless Profile Added',
  2701: 'Wireless Profile Removed',
  2702: 'Wireless Profile Updated',
  2800: 'EAC Posture Signer SET',
  2801: 'EAC Enabled',
  2802: 'EAC Disabled',
  2803: 'EAC Posture State',
  2804: 'EAC Set Options',
  2900: 'KVM Opt-in Enabled',
  2901: 'KVM Opt-in Disabled',
  2902: 'KVM Password Changed',
  2903: 'KVM Consent Succeeded',
  2904: 'KVM Consent Failed',
  3000: 'Opt-In Policy Change',
  3001: 'Send Consent Code Event',
  3002: 'Start Opt-In Blocked Event'
}

export const RealmNames = '||Redirection|PT Administration|Hardware Asset|Remote Control|Storage|Event Manager|Storage Admin|Agent Presence Local|Agent Presence Remote|Circuit Breaker|Network Time|General Information|Firmware Update|EIT|LocalUN|Endpoint Access Control|Endpoint Access Control Admin|Event Log Reader|Audit Log|ACL Realm|||Local System'.split('|')

export const VAULT_RESPONSE_CODES = (statusCode: any = null): string => {
  let vaultError: string
  if (statusCode != null) {
    switch (statusCode) {
      case 429:
        vaultError = 'unsealed and standby'
        break
      case 472:
        vaultError = 'disaster recovery mode replication secondary and active'
        break
      case 473:
        vaultError = 'performance standby'
        break
      case 501:
        vaultError = 'not initialized'
        break
      case 503:
        vaultError = 'sealed'
        break
      default:
        vaultError = 'unknown error'
        break
    }
  } else {
    vaultError = 'statusCode null'
  }

  return vaultError
}
