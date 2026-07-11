"""
AWS Network Architecture Review MCP Server
Public version — uses standard AWS SDK (boto3) only.
Uses only standard boto3 APIs — no proprietary dependencies.

Provides automated DX/TGW/Cloud WAN architecture assessments,
resiliency scoring, and BGP status analysis.
"""

import json
from collections import defaultdict
from mcp.server.fastmcp import FastMCP
import boto3

mcp = FastMCP("aws-network-architecture-review")


def get_client(service: str, region: str = "us-east-1"):
    """Get a boto3 client for the specified service and region."""
    return boto3.client(service, region_name=region)


def _get_key(data: dict, camel: str) -> list | dict:
    """Get a value from boto3 response handling both PascalCase and camelCase keys.
    boto3 returns PascalCase for top-level response keys (e.g., TransitGateways)
    but nested object fields remain camelCase (e.g., transitGatewayId).
    """
    # Try PascalCase first (boto3 default)
    pascal = camel[0].upper() + camel[1:]
    if pascal in data:
        return data[pascal]
    # Fallback to camelCase
    if camel in data:
        return data[camel]
    return []


# ─── Direct Connect Tools ───────────────────────────────────────────────────


@mcp.tool()
def analyze_dx_topology(region: str = "us-east-1") -> str:
    """
    Analyze AWS Direct Connect topology for the configured account.
    Returns connections, virtual interfaces, gateways, BGP status, and resiliency assessment.

    Args:
        region: AWS region (default us-east-1)
    """
    dx = get_client("directconnect", region)

    connections = dx.describe_connections().get("connections", dx.describe_connections().get("Connections", []))
    vifs = dx.describe_virtual_interfaces().get("virtualInterfaces", [])
    gateways = dx.describe_direct_connect_gateways().get("directConnectGateways", [])

    result = {
        "region": region,
        "summary": {
            "total_connections": len(connections),
            "total_virtual_interfaces": len(vifs),
            "total_dx_gateways": len(gateways),
        },
        "connections": [_format_connection(c) for c in connections],
        "virtual_interfaces": [_format_vif(v) for v in vifs],
        "dx_gateways": [_format_gateway(g) for g in gateways],
        "bgp_status": _analyze_bgp(vifs),
        "resiliency_assessment": _assess_resiliency(connections, vifs, gateways),
    }
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def check_dx_resiliency(region: str = "us-east-1") -> str:
    """
    Focused resiliency assessment for Direct Connect setup.
    Checks location diversity, redundancy, BGP health, MTU, and MACsec.

    Args:
        region: AWS region (default us-east-1)
    """
    dx = get_client("directconnect", region)

    connections = dx.describe_connections().get("connections", dx.describe_connections().get("Connections", []))
    vifs = dx.describe_virtual_interfaces().get("virtualInterfaces", [])
    gateways = dx.describe_direct_connect_gateways().get("directConnectGateways", [])

    assessment = _assess_resiliency(connections, vifs, gateways)
    return json.dumps(assessment, indent=2, default=str)


@mcp.tool()
def get_bgp_status(region: str = "us-east-1") -> str:
    """
    Get BGP peer status for all virtual interfaces in the account.

    Args:
        region: AWS region (default us-east-1)
    """
    dx = get_client("directconnect", region)
    vifs = dx.describe_virtual_interfaces().get("virtualInterfaces", [])
    bgp = _analyze_bgp(vifs)
    return json.dumps(bgp, indent=2, default=str)


@mcp.tool()
def get_dx_vif_details(region: str = "us-east-1", vif_id: str = "") -> str:
    """
    Get detailed Direct Connect Virtual Interface information.
    Returns VIF config, BGP peers, route filter prefixes, and associated DX gateway.

    Args:
        region: AWS region (default us-east-1)
        vif_id: Optional specific VIF ID (dxvif-xxx). If empty, returns all VIFs.
    """
    dx = get_client("directconnect", region)

    if vif_id:
        vifs = dx.describe_virtual_interfaces(virtualInterfaceId=vif_id).get("virtualInterfaces", [])
    else:
        vifs = dx.describe_virtual_interfaces().get("virtualInterfaces", [])

    if not vifs:
        return json.dumps({"region": region, "message": "No VIFs found"}, indent=2)

    vifs_detail = []
    for v in vifs:
        vifs_detail.append({
            "vif_id": v.get("virtualInterfaceId"),
            "name": v.get("virtualInterfaceName", ""),
            "type": v.get("virtualInterfaceType"),
            "state": v.get("virtualInterfaceState"),
            "connection_id": v.get("connectionId"),
            "location": v.get("location"),
            "vlan": v.get("vlan"),
            "mtu": v.get("mtu"),
            "jumbo_frame_capable": v.get("jumboFrameCapable", False),
            "amazon_address": v.get("amazonAddress"),
            "customer_address": v.get("customerAddress"),
            "address_family": v.get("addressFamily"),
            "amazon_side_asn": v.get("AmazonSideAsn"),
            "customer_asn": v.get("asn"),
            "dx_gateway_id": v.get("directConnectGatewayId"),
            "virtual_gateway_id": v.get("virtualGatewayId"),
            "route_filter_prefixes": [p.get("cidr") for p in v.get("routeFilterPrefixes", [])],
            "bgp_peers": [
                {
                    "asn": p.get("asn"),
                    "address_family": p.get("addressFamily"),
                    "amazon_address": p.get("amazonAddress"),
                    "customer_address": p.get("customerAddress"),
                    "state": p.get("bgpPeerState"),
                    "status": p.get("bgpStatus"),
                }
                for p in v.get("bgpPeers", [])
            ],
        })

    return json.dumps({"region": region, "total_vifs": len(vifs_detail), "virtual_interfaces": vifs_detail}, indent=2, default=str)


@mcp.tool()
def get_dx_gateway_details(region: str = "us-east-1", dx_gateway_id: str = "") -> str:
    """
    Get Direct Connect Gateway details including associations and attachments.
    Shows which VGWs/TGWs are associated and allowed prefixes.

    Args:
        region: AWS region (default us-east-1)
        dx_gateway_id: Optional specific DX Gateway ID. If empty, returns all.
    """
    dx = get_client("directconnect", region)

    if dx_gateway_id:
        gateways = dx.describe_direct_connect_gateways(directConnectGatewayId=dx_gateway_id).get("directConnectGateways", [])
    else:
        gateways = dx.describe_direct_connect_gateways().get("directConnectGateways", [])

    if not gateways:
        return json.dumps({"region": region, "message": "No DX Gateways found"}, indent=2)

    gateways_detail = []
    for gw in gateways:
        gw_id = gw.get("directConnectGatewayId")

        associations = dx.describe_direct_connect_gateway_associations(
            directConnectGatewayId=gw_id
        ).get("directConnectGatewayAssociations", [])

        attachments = dx.describe_direct_connect_gateway_attachments(
            directConnectGatewayId=gw_id
        ).get("directConnectGatewayAttachments", [])

        gateways_detail.append({
            "dx_gateway_id": gw_id,
            "name": gw.get("directConnectGatewayName"),
            "state": gw.get("directConnectGatewayState"),
            "amazon_side_asn": gw.get("amazonSideAsn"),
            "owner_account": gw.get("ownerAccount"),
            "associations": [
                {
                    "association_state": a.get("associationState"),
                    "associated_gateway_id": a.get("associatedGateway", {}).get("id"),
                    "associated_gateway_type": a.get("associatedGateway", {}).get("type"),
                    "associated_gateway_region": a.get("associatedGateway", {}).get("region"),
                    "allowed_prefixes": [p.get("cidr") for p in a.get("allowedPrefixesToDirectConnectGateway", [])],
                }
                for a in associations
            ],
            "attachments": [
                {
                    "virtual_interface_id": att.get("virtualInterfaceId"),
                    "virtual_interface_region": att.get("virtualInterfaceRegion"),
                    "attachment_state": att.get("attachmentState"),
                }
                for att in attachments
            ],
        })

    return json.dumps({"region": region, "dx_gateways": gateways_detail}, indent=2, default=str)


# ─── Transit Gateway Tools ──────────────────────────────────────────────────


@mcp.tool()
def analyze_tgw_topology(region: str = "us-east-1") -> str:
    """
    Analyze AWS Transit Gateway topology.
    Returns TGW details, attachments (VPC, VPN, peering, DX gateway), and route tables.

    Args:
        region: AWS region (default us-east-1)
    """
    ec2 = get_client("ec2", region)

    tgws = ec2.describe_transit_gateways().get("TransitGateways", [])
    if not tgws:
        return json.dumps({"region": region, "transit_gateways": [], "summary": "No TGWs found"}, indent=2)

    attachments = ec2.describe_transit_gateway_attachments().get("TransitGatewayAttachments", [])
    route_tables = ec2.describe_transit_gateway_route_tables().get("TransitGatewayRouteTables", [])

    result = {
        "region": region,
        "summary": {
            "total_tgws": len(tgws),
            "total_attachments": len(attachments),
            "total_route_tables": len(route_tables),
            "attachments_by_type": _count_by_key(attachments, "ResourceType"),
        },
        "transit_gateways": [
            {
                "id": t.get("TransitGatewayId"),
                "name": _get_name_tag(t.get("Tags", [])),
                "state": t.get("State"),
                "owner_id": t.get("OwnerId"),
                "asn": t.get("Options", {}).get("AmazonSideAsn"),
                "dns_support": t.get("Options", {}).get("DnsSupport"),
                "vpn_ecmp": t.get("Options", {}).get("VpnEcmpSupport"),
                "multicast": t.get("Options", {}).get("MulticastSupport"),
            }
            for t in tgws
        ],
        "attachments": [
            {
                "attachment_id": a.get("TransitGatewayAttachmentId"),
                "name": _get_name_tag(a.get("Tags", [])),
                "resource_type": a.get("ResourceType"),
                "resource_id": a.get("ResourceId"),
                "state": a.get("State"),
                "tgw_id": a.get("TransitGatewayId"),
            }
            for a in attachments
        ],
        "route_tables": [
            {
                "id": rt.get("TransitGatewayRouteTableId"),
                "name": _get_name_tag(rt.get("Tags", [])),
                "tgw_id": rt.get("TransitGatewayId"),
                "default_association": rt.get("DefaultAssociationRouteTable", False),
                "default_propagation": rt.get("DefaultPropagationRouteTable", False),
            }
            for rt in route_tables
        ],
    }
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def get_tgw_route_table_details(region: str = "us-east-1", tgw_id: str = "") -> str:
    """
    Deep-dive into TGW route tables: associations, propagations, and routes.

    Args:
        region: AWS region (default us-east-1)
        tgw_id: Optional TGW ID to filter. If empty, analyzes all TGWs.
    """
    ec2 = get_client("ec2", region)

    filters = [{"Name": "transit-gateway-id", "Values": [tgw_id]}] if tgw_id else []
    rt_list = ec2.describe_transit_gateway_route_tables(
        Filters=filters if filters else []
    ).get("TransitGatewayRouteTables", [])

    if not rt_list:
        return json.dumps({"region": region, "message": "No TGW route tables found"}, indent=2)

    route_tables_detail = []
    for rt in rt_list:
        rt_id = rt.get("TransitGatewayRouteTableId")

        associations = ec2.get_transit_gateway_route_table_associations(
            TransitGatewayRouteTableId=rt_id
        ).get("Associations", [])

        propagations = ec2.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId=rt_id
        ).get("TransitGatewayRouteTablePropagations", [])

        routes = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rt_id,
            Filters=[{"Name": "state", "Values": ["active", "blackhole"]}]
        ).get("Routes", [])

        route_tables_detail.append({
            "route_table_id": rt_id,
            "name": _get_name_tag(rt.get("Tags", [])),
            "tgw_id": rt.get("TransitGatewayId"),
            "associations": [
                {"attachment_id": a.get("TransitGatewayAttachmentId"), "resource_type": a.get("ResourceType"), "resource_id": a.get("ResourceId")}
                for a in associations
            ],
            "propagations": [
                {"attachment_id": p.get("TransitGatewayAttachmentId"), "resource_type": p.get("ResourceType"), "resource_id": p.get("ResourceId")}
                for p in propagations
            ],
            "routes": [
                {
                    "cidr": r.get("DestinationCidrBlock"),
                    "type": r.get("Type"),
                    "state": r.get("State"),
                    "attachments": [{"attachment_id": att.get("TransitGatewayAttachmentId"), "resource_type": att.get("ResourceType"), "resource_id": att.get("ResourceId")} for att in r.get("TransitGatewayAttachments", [])],
                }
                for r in routes
            ],
            "summary": {
                "total_associations": len(associations),
                "total_propagations": len(propagations),
                "total_routes": len(routes),
                "blackhole_routes": sum(1 for r in routes if r.get("State") == "blackhole"),
            },
        })

    return json.dumps({"region": region, "route_tables": route_tables_detail}, indent=2, default=str)


@mcp.tool()
def get_virtual_gateway_details(region: str = "us-east-1") -> str:
    """
    Get Virtual Private Gateway (VGW) details including attached VPCs.

    Args:
        region: AWS region (default us-east-1)
    """
    ec2 = get_client("ec2", region)
    vgws = ec2.describe_vpn_gateways().get("VpnGateways", [])

    if not vgws:
        return json.dumps({"region": region, "message": "No Virtual Gateways found"}, indent=2)

    return json.dumps({
        "region": region,
        "virtual_gateways": [
            {
                "vgw_id": v.get("VpnGatewayId"),
                "name": _get_name_tag(v.get("Tags", [])),
                "state": v.get("state"),
                "type": v.get("Type"),
                "amazon_side_asn": v.get("AmazonSideAsn"),
                "vpc_attachments": [{"vpc_id": a.get("vpcId"), "state": a.get("State")} for a in v.get("VpcAttachments", [])],
            }
            for v in vgws
        ],
    }, indent=2, default=str)


# ─── Cloud WAN Tools ────────────────────────────────────────────────────────


@mcp.tool()
def analyze_cloudwan_topology(region: str = "us-east-1") -> str:
    """
    Analyze AWS Cloud WAN topology.
    Returns global networks, core networks, attachments, and peerings.

    Args:
        region: AWS region (default us-east-1)
    """
    nm = get_client("networkmanager", region)

    global_networks = nm.describe_global_networks().get("GlobalNetworks", [])
    if not global_networks:
        return json.dumps({"region": region, "message": "No Cloud WAN global networks found"}, indent=2)

    core_networks = nm.list_core_networks().get("CoreNetworks", [])
    attachments = nm.list_attachments().get("Attachments", [])
    peerings = nm.list_peerings().get("Peerings", [])

    result = {
        "region": region,
        "summary": {
            "total_global_networks": len(global_networks),
            "total_core_networks": len(core_networks),
            "total_attachments": len(attachments),
            "total_peerings": len(peerings),
            "attachments_by_type": _count_by_key(attachments, "AttachmentType"),
        },
        "global_networks": [{"id": g.get("GlobalNetworkId"), "State": g.get("state"), "description": g.get("Description", "")} for g in global_networks],
        "core_networks": [{"id": cn.get("CoreNetworkId"), "State": cn.get("state"), "description": cn.get("Description", "")} for cn in core_networks],
        "attachments": [
            {
                "attachment_id": a.get("AttachmentId"),
                "core_network_id": a.get("CoreNetworkId"),
                "attachment_type": a.get("AttachmentType"),
                "state": a.get("State"),
                "edge_location": a.get("EdgeLocation"),
                "segment_name": a.get("SegmentName", ""),
            }
            for a in attachments
        ],
        "peerings": [
            {"peering_id": p.get("PeeringId"), "peering_type": p.get("PeeringType"), "State": p.get("state"), "edge_location": p.get("EdgeLocation")}
            for p in peerings
        ],
    }
    return json.dumps(result, indent=2, default=str)


# ─── VPC Endpoints Tool ─────────────────────────────────────────────────────


@mcp.tool()
def get_vpc_endpoints(region: str = "us-east-1") -> str:
    """
    List VPC endpoints with summary by type.
    Detects centralized vs distributed endpoint patterns.

    Args:
        region: AWS region (default us-east-1)
    """
    ec2 = get_client("ec2", region)
    endpoints = []
    paginator = ec2.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate():
        endpoints.extend(page.get("VpcEndpoints", []))

    if not endpoints:
        return json.dumps({"region": region, "message": "No VPC endpoints found"}, indent=2)

    by_vpc = defaultdict(int)
    by_type = defaultdict(int)
    entries = []

    for ep in endpoints:
        ep_type = ep.get("VpcEndpointType", "Unknown")
        vpc_id = ep.get("VpcId", "")
        by_type[ep_type] += 1
        by_vpc[vpc_id] += 1
        entries.append({
            "endpoint_id": ep.get("VpcEndpointId"),
            "service": ep.get("ServiceName", "").split(".")[-1],
            "type": ep_type,
            "vpc_id": vpc_id,
            "state": ep.get("State"),
            "private_dns": ep.get("PrivateDnsEnabled", False),
        })

    max_vpc = max(by_vpc, key=by_vpc.get)
    pattern = "centralized" if by_vpc[max_vpc] > len(endpoints) * 0.5 else "distributed"

    return json.dumps({
        "region": region,
        "summary": {"total": len(endpoints), "by_type": dict(by_type), "pattern": pattern},
        "endpoints": entries,
    }, indent=2, default=str)


# ─── VPN Tool ────────────────────────────────────────────────────────────────


@mcp.tool()
def get_vpn_details(region: str = "us-east-1") -> str:
    """
    Get VPN connection details including tunnel status and BGP configuration.

    Args:
        region: AWS region (default us-east-1)
    """
    ec2 = get_client("ec2", region)
    vpns = ec2.describe_vpn_connections().get("VpnConnections", [])

    if not vpns:
        return json.dumps({"region": region, "message": "No VPN connections found"}, indent=2)

    vpn_details = []
    for v in vpns:
        tunnels = []
        for t in v.get("VgwTelemetry", []):
            tunnels.append({
                "outside_ip": t.get("outsideIpAddress"),
                "status": t.get("status"),
                "status_message": t.get("statusMessage", ""),
                "accepted_routes": t.get("acceptedRouteCount", 0),
            })

        vpn_details.append({
            "vpn_id": v.get("VpnConnectionId"),
            "state": v.get("state"),
            "type": v.get("Type"),
            "category": v.get("Category"),
            "tgw_id": v.get("TransitGatewayId"),
            "vgw_id": v.get("VpnGatewayId"),
            "customer_gateway_id": v.get("CustomerGatewayId"),
            "customer_gateway_ip": v.get("customerGatewayConfiguration", "")[:0],  # Don't expose config
            "tunnels": tunnels,
            "static_routes": [r.get("DestinationCidrBlock") for r in v.get("routes", [])],
            "tags": {tag["Key"]: tag["Value"] for tag in v.get("Tags", []) if tag.get("Key")},
        })

    tunnels_up = sum(1 for vpn in vpn_details for t in vpn["tunnels"] if t["status"] == "UP")
    tunnels_total = sum(len(vpn["tunnels"]) for vpn in vpn_details)

    return json.dumps({
        "region": region,
        "total_vpns": len(vpn_details),
        "tunnels_up": tunnels_up,
        "tunnels_total": tunnels_total,
        "vpn_connections": vpn_details,
    }, indent=2, default=str)


# ─── CloudWatch Metrics Tool ────────────────────────────────────────────────


@mcp.tool()
def get_dx_cloudwatch_metrics(region: str = "us-east-1", connection_id: str = "", hours: int = 3) -> str:
    """
    Get Direct Connect CloudWatch metrics: utilization, errors, and packet loss.
    Returns ingress/egress bandwidth, connection state, and error counts.

    Args:
        region: AWS region (default us-east-1)
        connection_id: DX connection ID (dxcon-xxx). If empty, gets metrics for all connections.
        hours: Lookback period in hours (default 3)
    """
    from datetime import datetime, timedelta, timezone

    dx = get_client("directconnect", region)
    cw = get_client("cloudwatch", region)

    # Get connection IDs if not specified
    if connection_id:
        conn_ids = [connection_id]
    else:
        connections = dx.describe_connections().get("connections", dx.describe_connections().get("Connections", []))
        conn_ids = [c["connectionId"] for c in connections if c.get("connectionState") == "available"]

    if not conn_ids:
        return json.dumps({"region": region, "message": "No available DX connections found"}, indent=2)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    period = 300  # 5-minute intervals

    metrics_result = []
    for cid in conn_ids:
        dimensions = [{"Name": "ConnectionId", "Value": cid}]

        # Fetch key metrics
        metric_queries = [
            {"id": "ingress", "metric": "ConnectionBpsIngress", "stat": "Average"},
            {"id": "egress", "metric": "ConnectionBpsEgress", "stat": "Average"},
            {"id": "ingress_max", "metric": "ConnectionBpsIngress", "stat": "Maximum"},
            {"id": "egress_max", "metric": "ConnectionBpsEgress", "stat": "Maximum"},
            {"id": "state", "metric": "ConnectionState", "stat": "Minimum"},
            {"id": "errors_in", "metric": "ConnectionErrorCount", "stat": "Sum"},
            {"id": "light_in", "metric": "ConnectionLightLevelRx", "stat": "Average"},
            {"id": "light_out", "metric": "ConnectionLightLevelTx", "stat": "Average"},
        ]

        queries = []
        for i, mq in enumerate(metric_queries):
            queries.append({
                "Id": mq["id"],
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/DX",
                        "MetricName": mq["metric"],
                        "Dimensions": dimensions,
                    },
                    "Period": period,
                    "Stat": mq["stat"],
                },
            })

        try:
            resp = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start_time,
                EndTime=end_time,
            )

            metrics = {}
            for result in resp.get("MetricDataResults", []):
                values = result.get("Values", [])
                if values:
                    metrics[result["Id"]] = {
                        "avg": round(sum(values) / len(values), 2),
                        "max": round(max(values), 2),
                        "min": round(min(values), 2),
                        "datapoints": len(values),
                    }

            # Convert bps to readable
            ingress_avg = metrics.get("ingress", {}).get("avg", 0)
            egress_avg = metrics.get("egress", {}).get("avg", 0)
            ingress_max = metrics.get("ingress_max", {}).get("max", 0)
            egress_max = metrics.get("egress_max", {}).get("max", 0)

            metrics_result.append({
                "connection_id": cid,
                "period_hours": hours,
                "ingress": {
                    "avg_mbps": round(ingress_avg / 1_000_000, 2),
                    "peak_mbps": round(ingress_max / 1_000_000, 2),
                },
                "egress": {
                    "avg_mbps": round(egress_avg / 1_000_000, 2),
                    "peak_mbps": round(egress_max / 1_000_000, 2),
                },
                "connection_state": metrics.get("state", {}).get("min", "N/A"),
                "errors": metrics.get("errors_in", {}).get("avg", 0),
                "light_levels": {
                    "rx_dbm": metrics.get("light_in", {}).get("avg", "N/A"),
                    "tx_dbm": metrics.get("light_out", {}).get("avg", "N/A"),
                },
            })
        except Exception as e:
            metrics_result.append({"connection_id": cid, "error": str(e)})

    return json.dumps({"region": region, "metrics": metrics_result}, indent=2, default=str)


# ─── Architecture Summary Tool ──────────────────────────────────────────────


@mcp.tool()
def network_architecture_summary(region: str = "us-east-1") -> str:
    """
    Complete network architecture discovery using public AWS APIs.
    Combines DX, TGW, VPN, VGW, Cloud WAN, VPC endpoints, and CloudWatch metrics
    into a single comprehensive response for architecture report generation.

    Args:
        region: AWS region (default us-east-1)
    """
    from datetime import datetime, timedelta, timezone

    dx = get_client("directconnect", region)
    ec2 = get_client("ec2", region)
    cw = get_client("cloudwatch", region)
    nm = get_client("networkmanager", region)

    # ─── DX Layer ───
    connections = dx.describe_connections().get("connections", [])
    vifs = dx.describe_virtual_interfaces().get("virtualInterfaces", [])
    gateways = dx.describe_direct_connect_gateways().get("directConnectGateways", [])

    # DX Gateway associations
    gw_details = []
    for gw in gateways:
        gw_id = gw.get("directConnectGatewayId")
        assocs = dx.describe_direct_connect_gateway_associations(
            directConnectGatewayId=gw_id
        ).get("directConnectGatewayAssociations", [])
        gw_details.append({
            "id": gw_id,
            "name": gw.get("directConnectGatewayName"),
            "asn": gw.get("amazonSideAsn"),
            "associations": len(assocs),
            "allowed_prefixes": sum(len(a.get("allowedPrefixesToDirectConnectGateway", [])) for a in assocs),
        })

    # ─── DX CloudWatch Metrics ───
    dx_metrics = []
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=3)
    for conn in connections:
        cid = conn.get("connectionId")
        if conn.get("connectionState") != "available":
            continue
        try:
            resp = cw.get_metric_data(
                MetricDataQueries=[
                    {"Id": "ingress", "MetricStat": {"Metric": {"Namespace": "AWS/DX", "MetricName": "ConnectionBpsIngress", "Dimensions": [{"Name": "ConnectionId", "Value": cid}]}, "Period": 300, "Stat": "Average"}},
                    {"Id": "egress", "MetricStat": {"Metric": {"Namespace": "AWS/DX", "MetricName": "ConnectionBpsEgress", "Dimensions": [{"Name": "ConnectionId", "Value": cid}]}, "Period": 300, "Stat": "Average"}},
                ],
                StartTime=start_time, EndTime=end_time,
            )
            metrics = {}
            for r in resp.get("MetricDataResults", []):
                vals = r.get("Values", [])
                if vals:
                    metrics[r["Id"]] = round(sum(vals) / len(vals) / 1_000_000, 2)
            dx_metrics.append({"connection_id": cid, "avg_ingress_mbps": metrics.get("ingress", 0), "avg_egress_mbps": metrics.get("egress", 0)})
        except Exception:
            pass

    # ─── TGW Layer ───
    tgws = ec2.describe_transit_gateways().get("TransitGateways", [])
    tgw_attachments = ec2.describe_transit_gateway_attachments().get("TransitGatewayAttachments", []) if tgws else []

    tgw_details = []
    for t in tgws:
        tgw_details.append({
            "id": t.get("TransitGatewayId"),
            "name": _get_name_tag(t.get("Tags", [])),
            "asn": t.get("Options", {}).get("AmazonSideAsn"),
            "state": t.get("State"),
        })

    # ─── VPN Layer ───
    vpns = ec2.describe_vpn_connections().get("VpnConnections", [])
    vpn_details = []
    for v in vpns:
        tunnels = v.get("VgwTelemetry", [])
        vpn_details.append({
            "vpn_id": v.get("VpnConnectionId"),
            "name": _get_name_tag(v.get("Tags", [])),
            "state": v.get("State"),
            "tgw_id": v.get("TransitGatewayId"),
            "tunnels_up": sum(1 for t in tunnels if t.get("Status") == "UP"),
            "tunnels_total": len(tunnels),
        })

    # ─── VGW Layer ───
    vgws = ec2.describe_vpn_gateways().get("VpnGateways", [])
    vgw_details = [
        {
            "id": v.get("VpnGatewayId"),
            "name": _get_name_tag(v.get("Tags", [])),
            "asn": v.get("AmazonSideAsn"),
            "attached_vpcs": [a.get("VpcId") for a in v.get("VpcAttachments", []) if a.get("State") == "attached"],
        }
        for v in vgws
    ]

    # ─── Cloud WAN Layer ───
    cloudwan = {}
    try:
        global_networks = nm.describe_global_networks().get("GlobalNetworks", [])
        if global_networks:
            core_networks = nm.list_core_networks().get("CoreNetworks", [])
            cw_attachments = nm.list_attachments().get("Attachments", [])
            cloudwan = {
                "global_networks": len(global_networks),
                "core_networks": len(core_networks),
                "attachments": len(cw_attachments),
                "attachments_by_type": _count_by_key(cw_attachments, "AttachmentType"),
                "edge_locations": list(set(a.get("EdgeLocation", "") for a in cw_attachments)),
            }
    except Exception:
        pass

    # ─── VPC Endpoints ───
    endpoints = []
    try:
        paginator = ec2.get_paginator("describe_vpc_endpoints")
        for page in paginator.paginate():
            endpoints.extend(page.get("VpcEndpoints", []))
    except Exception:
        pass

    endpoint_summary = {}
    if endpoints:
        by_type = defaultdict(int)
        for ep in endpoints:
            by_type[ep.get("VpcEndpointType", "Unknown")] += 1
        endpoint_summary = {"total": len(endpoints), "by_type": dict(by_type)}

    # ─── VPCs ───
    vpcs = ec2.describe_vpcs().get("Vpcs", [])

    # ─── Detect Pattern ───
    if tgws and connections and cloudwan:
        pattern = "Cloud WAN + TGW + Direct Connect (hybrid multi-region)"
    elif cloudwan:
        pattern = "Cloud WAN with VPC attachments"
    elif tgws and connections:
        pattern = "Hub-spoke via TGW with Direct Connect"
    elif tgws and vpns:
        pattern = "Hub-spoke via TGW with VPN"
    elif connections:
        pattern = "Direct Connect with VGW (no TGW)"
    else:
        pattern = "Standalone VPCs"

    locations = list(set(c.get("location", "") for c in connections))

    result = {
        "region": region,
        "connectivity_pattern": pattern,
        "dx": {
            "connections": [_format_connection(c) for c in connections],
            "virtual_interfaces": [_format_vif(v) for v in vifs],
            "gateways": gw_details,
            "locations": locations,
            "bgp_health": _analyze_bgp(vifs),
            "metrics": dx_metrics,
        },
        "tgw": {
            "transit_gateways": tgw_details,
            "total_attachments": len(tgw_attachments),
            "attachments_by_type": _count_by_key(tgw_attachments, "ResourceType"),
        },
        "vpn": {
            "connections": vpn_details,
            "tunnels_up": sum(v["tunnels_up"] for v in vpn_details),
            "tunnels_total": sum(v["tunnels_total"] for v in vpn_details),
        },
        "vgw": vgw_details,
        "cloud_wan": cloudwan,
        "vpc_endpoints": endpoint_summary,
        "vpcs": {"total": len(vpcs)},
        "resiliency": _assess_resiliency(connections, vifs, gateways),
        "redundancy": {
            "dx_locations": len(locations),
            "dx_connections": len(connections),
            "vpn_backup": len(vpns) > 0,
            "macsec_capable": any(c.get("macSecCapable") for c in connections),
            "macsec_enabled": any(c.get("macSecKeys") for c in connections),
        },
    }
    return json.dumps(result, indent=2, default=str)


# ─── Helpers ────────────────────────────────────────────────────────────────


def _format_connection(c):
    return {
        "id": c.get("connectionId"),
        "name": c.get("connectionName", ""),
        "state": c.get("connectionState"),
        "bandwidth": c.get("bandwidth", ""),
        "location": c.get("location", ""),
        "region": c.get("region", ""),
        "partner": c.get("partnerName", ""),
        "lag_id": c.get("lagId"),
        "macsec_capable": c.get("macSecCapable", False),
    }


def _format_vif(v):
    return {
        "id": v.get("virtualInterfaceId"),
        "name": v.get("virtualInterfaceName", ""),
        "type": v.get("virtualInterfaceType"),
        "state": v.get("virtualInterfaceState"),
        "connection_id": v.get("connectionId"),
        "vlan": v.get("vlan"),
        "mtu": v.get("mtu"),
        "dx_gateway_id": v.get("directConnectGatewayId", ""),
        "bgp_peers": [
            {"asn": p.get("asn"), "state": p.get("bgpPeerState"), "status": p.get("bgpStatus")}
            for p in v.get("bgpPeers", [])
        ],
    }


def _format_gateway(gw):
    return {
        "id": gw.get("directConnectGatewayId"),
        "name": gw.get("directConnectGatewayName", ""),
        "state": gw.get("directConnectGatewayState"),
        "asn": gw.get("amazonSideAsn"),
    }


def _analyze_bgp(vifs):
    peers_up = peers_down = peers_total = 0
    issues = []
    for v in vifs:
        for p in v.get("bgpPeers", []):
            peers_total += 1
            if p.get("bgpStatus") == "up":
                peers_up += 1
            else:
                peers_down += 1
                issues.append({"vif": v.get("virtualInterfaceId"), "status": p.get("bgpStatus")})
    return {
        "total_peers": peers_total,
        "peers_up": peers_up,
        "peers_down": peers_down,
        "health_pct": round((peers_up / peers_total * 100) if peers_total > 0 else 0, 1),
        "down_peers": issues,
    }


def _assess_resiliency(connections, vifs, gateways):
    findings = []
    score = 100

    locations = [c.get("location", "") for c in connections if c.get("connectionState") == "available"]
    unique_locations = set(locations)

    if not connections:
        return {"resiliency_level": "N/A", "score": 0, "findings": [{"severity": "INFO", "check": "DX Presence", "finding": "No DX connections found."}]}

    # Location diversity
    if len(unique_locations) < 2:
        findings.append({"severity": "CRITICAL", "check": "Location Diversity", "finding": f"All connections in single location: {list(unique_locations)}"})
        score -= 40
    else:
        findings.append({"severity": "OK", "check": "Location Diversity", "finding": f"Connections span {len(unique_locations)} locations"})

    # Redundancy per location
    location_counts = defaultdict(int)
    for c in connections:
        if c.get("connectionState") == "available":
            location_counts[c.get("location", "unknown")] += 1
    for loc, count in location_counts.items():
        if count < 2:
            findings.append({"severity": "HIGH", "check": "Connection Redundancy", "finding": f"Location {loc} has only {count} connection(s)"})
            score -= 15

    # BGP health
    bgp = _analyze_bgp(vifs)
    if bgp["peers_down"] > 0:
        findings.append({"severity": "HIGH", "check": "BGP Health", "finding": f"{bgp['peers_down']}/{bgp['total_peers']} BGP peers DOWN"})
        score -= 10 * bgp["peers_down"]

    # MTU consistency
    mtus = set(v.get("mtu", 1500) for v in vifs)
    if len(mtus) > 1:
        findings.append({"severity": "MEDIUM", "check": "MTU Consistency", "finding": f"Mixed MTU values: {sorted(mtus)}"})
        score -= 5

    # MACsec
    macsec_capable = [c for c in connections if c.get("macSecCapable")]
    macsec_active = [c for c in connections if c.get("macSecKeys")]
    if macsec_capable and not macsec_active:
        findings.append({"severity": "MEDIUM", "check": "MACsec", "finding": f"{len(macsec_capable)} connection(s) MACsec-capable but not enabled"})
        score -= 5

    # Determine level
    if len(unique_locations) >= 2 and all(c >= 2 for c in location_counts.values()):
        level = "HIGH (Maximum Resiliency)"
    elif len(unique_locations) >= 2:
        level = "MEDIUM (High Resiliency)"
    else:
        level = "LOW (Single Location)"

    return {"resiliency_level": level, "score": max(0, score), "findings": findings}


def _count_by_key(items, key):
    counts = defaultdict(int)
    for item in items:
        counts[item.get(key, "unknown")] += 1
    return dict(counts)


def _get_name_tag(tags):
    for tag in tags:
        if tag.get("Key") == "Name" or tag.get("key") == "Name":
            return tag.get("Value", tag.get("value", ""))
    return ""


if __name__ == "__main__":
    mcp.run()
