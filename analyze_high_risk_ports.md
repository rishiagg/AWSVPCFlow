**Title: Analyzing Network Traffic to High-Risk Ports**

**Description:**
This KQL query helps analyze network traffic within a specific time range, focusing on identifying connections to high-risk ports. The query filters data from the "AWSVPCFlow" table in Azure Sentinel based on criteria such as time range, IP address ranges, log status, and specific protocol and destination port values. The query then projects relevant fields to provide insights into the source and destination IP addresses, whether they are internal or external, and the destination port numbers.

**Query:**
```kql
AWSVPCFlow
| where TimeGenerated >= ago(6h)
| extend IsSrcAddrInternalIP = case(ipv4_is_in_range(SrcAddr, '10.0.0.0/8') or ipv4_is_in_range(SrcAddr, '172.16.0.0/12') or ipv4_is_in_range(SrcAddr, '192.168.0.0/16'), true, false)
| extend IsDstAddrInternalIP = case(ipv4_is_in_range(DstAddr, '10.0.0.0/8') or ipv4_is_in_range(DstAddr, '172.16.0.0/12') or ipv4_is_in_range(DstAddr, '192.168.0.0/16'), true, false)
| where LogStatus == "OK"
| where Protocol == 6 and (DstPort == 1337 or DstPort == 31337)
| project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, DstPort
```

**Explanation:**
1. **Title:** Analyzing Network Traffic to High-Risk Ports

2. **Description:** This KQL query helps identify network traffic patterns within the last 6 hours and focuses on connections made to high-risk ports. It leverages the "AWSVPCFlow" table in Azure Sentinel and filters the data based on specific conditions such as time range, IP address ranges, log status, protocol, and destination port values. The query projects relevant fields to provide insights into the source and destination IP addresses, whether they are internal or external, and the destination port numbers.

3. The query begins by selecting data from the "AWSVPCFlow" table within the last 6 hours (`TimeGenerated >= ago(6h)`).

4. Two new columns, `IsSrcAddrInternalIP` and `IsDstAddrInternalIP`, are added using the `extend` operator. These columns are assigned boolean values based on whether the source and destination IP addresses fall within the defined internal IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`).

5. The `where` clause filters the data further by checking the log status, ensuring only records with a log status of "OK" are considered.

6. Another `where` clause filters the data based on the protocol and destination port values. In this case, the protocol is set to `6` (TCP), and the destination ports are filtered to include only those with values `1337` or `31337`.

7. Finally, the `project` operator is used to project the source address (`SrcAddr`), internal/external flag for the source address (`IsSrcAddrInternalIP`), destination address (`DstAddr`), internal/external flag for the destination address (`IsDstAddrInternalIP`), and the destination port number (`DstPort`).

**Markdown File Name:** analyze_high_risk_ports.md
