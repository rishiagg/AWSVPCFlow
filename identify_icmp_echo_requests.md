**Title: Identifying ICMP Echo Requests with Destination Port 0**

**Description:**
This KQL query allows you to identify ICMP Echo Requests with a destination port of 0 within the last hour. By utilizing data from the "AWSVPCFlow" table in Azure Sentinel, the query filters the data based on criteria such as the time range, IP address ranges, log status, protocol, and destination port. The query projects relevant fields to provide insights into the source and destination IP addresses, whether they are internal or external, and the destination port number.

**Query:**
```kql
AWSVPCFlow
| where TimeGenerated >= ago(1h)
| extend IsSrcAddrInternalIP = case(ipv4_is_in_range(SrcAddr, '10.0.0.0/8') or ipv4_is_in_range(SrcAddr, '172.16.0.0/12') or ipv4_is_in_range(SrcAddr, '192.168.0.0/16'), true, false)
| extend IsDstAddrInternalIP = case(ipv4_is_in_range(DstAddr, '10.0.0.0/8') or ipv4_is_in_range(DstAddr, '172.16.0.0/12') or ipv4_is_in_range(DstAddr, '192.168.0.0/16'), true, false)
| where LogStatus == "OK"
| where Protocol == 1
| where DstPort == 0
| project SrcAddr, IsSrcAddrInternalIP, DstAddr, IsDstAddrInternalIP, DstPort
```

**Explanation:**
1. **Title:** Identifying ICMP Echo Requests with Destination Port 0

2. **Description:** This KQL query helps you identify instances of ICMP Echo Requests (Ping) with a destination port of 0 within the last hour. By using the "AWSVPCFlow" table in Azure Sentinel, the query filters the data based on specific criteria including the time range, IP address ranges, log status, protocol, and destination port. The query projects relevant fields to provide insights into the source and destination IP addresses, whether they are internal or external, and the destination port number.

3. The query starts by selecting data from the "AWSVPCFlow" table within the last hour (`TimeGenerated >= ago(1h)`).

4. Two new columns, `IsSrcAddrInternalIP` and `IsDstAddrInternalIP`, are added using the `extend` operator. These columns are assigned boolean values based on whether the source and destination IP addresses fall within the defined internal IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`).

5. The `where` clause filters the data further by checking the log status, ensuring only records with a log status of "OK" are considered.

6. Another `where` clause filters the data based on the protocol value. In this case, the protocol is set to `1`, which corresponds to ICMP (Internet Control Message Protocol) used for Ping requests.

7. The next `where` clause filters the data based on the destination port value. Here, the destination port is set to `0`, indicating ICMP Echo Requests where the destination port is not specified.

8. Finally, the `project` operator is used to project the source address (`SrcAddr`), internal/external flag for the source address (`IsSrcAddrInternalIP`), destination address (`DstAddr`), internal/external flag for the destination address (`IsDstAddrInternalIP`), and the destination port number (`DstPort`).
