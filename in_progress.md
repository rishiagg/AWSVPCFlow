**1. Internal Hosts Communicating with External IP Addresses:**
- Title: Internal Hosts Communicating with External IP Addresses
- Description: Identify internal hosts that are communicating with external IP addresses in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(6h)
  | where LogStatus == "OK"
  | where IsSrcAddrInternalIP == true and IsDstAddrInternalIP == false
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP
  ```
- File Name: `internal-hosts-communicating-external-ips.md`

**2. Inbound RDP Traffic to Internal Resources:**
- Title: Inbound RDP Traffic to Internal Resources
- Description: Detect inbound Remote Desktop Protocol (RDP) traffic to internal resources in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(12h)
  | where LogStatus == "OK"
  | where Protocol == 6 and DstPort == 3389 and IsDstAddrInternalIP == true
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP
  ```
- File Name: `inbound-rdp-traffic-to-internal-resources.md`

**3. Outbound SSH Traffic from Internal Network:**
- Title: Outbound SSH Traffic from Internal Network
- Description: Monitor outbound Secure Shell (SSH) traffic from your internal network in the AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(1h)
  | where LogStatus == "OK"
  | where Protocol == 6 and SrcPort == 22 and IsSrcAddrInternalIP == true
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP
  ```
- File Name: `outbound-ssh-traffic-from-internal-network.md`

**4. Large Incoming Network Traffic Flows:**
- Title: Large Incoming Network Traffic Flows
- Description: Identify large incoming network traffic flows exceeding a specified threshold in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(24h)
  | where LogStatus == "OK"
  | where Bytes > 100000000
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, Bytes
  ```
- File Name: `large-incoming-network-traffic-flows.md`

**5. Unusual ICMP Traffic Patterns:**
- Title: Unusual ICMP Traffic Patterns
- Description: Detect unusual Internet Control Message Protocol (ICMP) traffic patterns in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(6h)
  | where LogStatus == "OK"
  | where Protocol == 1 and (SrcPort != 0 or DstPort != 0)
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, Protocol, SrcPort, DstPort
  ```
- File Name: `unusual-icmp-traffic-patterns.md`

**6. Internal Hosts Accessing Suspicious Domains:**
- Title: Internal Hosts Accessing Suspicious Domains
- Description: Identify internal hosts accessing suspicious or

 malicious domains in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(12h)
  | where LogStatus == "OK"
  | where IsSrcAddrInternalIP == true and DstPort == 53
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP
  ```
- File Name: `internal-hosts-accessing-suspicious-domains.md`

**7. Large Outgoing Network Traffic Flows:**
- Title: Large Outgoing Network Traffic Flows
- Description: Identify large outgoing network traffic flows exceeding a specified threshold in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(1h)
  | where LogStatus == "OK"
  | where Bytes > 50000000
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, Bytes
  ```
- File Name: `large-outgoing-network-traffic-flows.md`

**8. Port Scanning Activity:**
- Title: Port Scanning Activity
- Description: Detect potential port scanning activity targeting internal resources in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(24h)
  | where LogStatus == "OK"
  | where Protocol == 6 and DstPort >= 1 and DstPort <= 1023 and IsDstAddrInternalIP == true
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, DstPort
  ```
- File Name: `port-scanning-activity.md`

**9. Suspicious UDP Traffic Patterns:**
- Title: Suspicious UDP Traffic Patterns
- Description: Identify suspicious User Datagram Protocol (UDP) traffic patterns in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(6h)
  | where LogStatus == "OK"
  | where Protocol == 17 and (SrcPort != 0 or DstPort != 0)
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, Protocol, SrcPort, DstPort
  ```
- File Name: `suspicious-udp-traffic-patterns.md`

**10. Uncommon Protocols Usage:**
- Title: Uncommon Protocols Usage
- Description: Identify uncommon or non-standard protocols being used in your AWS VPC flow logs.
- KQL Query:
  ```
  AWSVPCFlow
  | where TimeGenerated >= ago(12h)
  | where LogStatus == "OK"
  | where Protocol != 6 and Protocol != 17
  | project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, Protocol
  ```
- File Name: `uncommon-protocols-usage.md`

Feel free to customize these use cases further according to your specific security monitoring needs and thresholds.
