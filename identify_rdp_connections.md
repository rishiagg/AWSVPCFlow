**Title: Identifying Remote Desktop Protocol (RDP) Connections to Internal IP Addresses**

**Description:**
This KQL query allows you to identify Remote Desktop Protocol (RDP) connections made to internal IP addresses within a specific time range. It utilizes data from the "AWSVPCFlow" table in Azure Sentinel and filters the data based on conditions such as time range, IP address ranges, log status, protocol, and destination port. The query projects relevant fields to provide insights into the source and destination IP addresses, whether they are internal or external, and the destination port number.

**Query:**
```kql
AWSVPCFlow
| where TimeGenerated >= ago(12h)
| extend IsSrcAddrInternalIP = case(ipv4_is_in_range(SrcAddr, '10.0.0.0/8') or ipv4_is_in_range(SrcAddr, '172.16.0.0/12') or ipv4_is_in_range(SrcAddr, '192.168.0.0/16'), true, false)
| extend IsDstAddrInternalIP = case(ipv4_is_in_range(DstAddr, '10.0.0.0/8') or ipv4_is_in_range(DstAddr, '172.16.0.0/12') or ipv4_is_in_range(DstAddr, '192.168.0.0/16'), true, false)
| where LogStatus == "OK"
| where Protocol == 6 and DstPort == 3389
| project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, DstPort
```

**Explanation:**
1. **Title:** Identifying Remote Desktop Protocol (RDP) Connections to Internal IP Addresses

2. **Description:** This KQL query helps you identify instances of Remote Desktop Protocol (RDP) connections made to internal IP addresses within the last 12 hours. By using the "AWSVPCFlow" table in Azure Sentinel, the query filters the data based on specific criteria including the time range, IP address ranges, log status, protocol, and destination port. The query projects relevant fields to provide insights into the source and destination IP addresses, whether they are internal or external, and the destination port number.

3. The query starts by selecting data from the "AWSVPCFlow" table within the last 12 hours (`TimeGenerated >= ago(12h)`).

4. Two new columns, `IsSrcAddrInternalIP` and `IsDstAddrInternalIP`, are added using the `extend` operator. These columns are assigned boolean values based on whether the source and destination IP addresses fall within the defined internal IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`).

5. The `where` clause filters the data further by checking the log status, ensuring only records with a log status of "OK" are considered.

6. Another `where` clause filters the data based on the protocol and destination port values. In this case, the protocol is set to `6` (TCP), and the destination port is set to `3389`, which is commonly used for RDP connections.

7. Finally, the `project` operator is used to project the source address (`SrcAddr`), internal/external flag for the source address (`IsSrcAddrInternalIP`), destination address (`DstAddr`), internal/external flag for the destination address (`IsDstAddrInternalIP`), and the destination port number (`DstPort`).

**Markdown File Name:** identify_rdp_connections.md
