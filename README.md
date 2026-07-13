# AWS Network Architecture Review MCP Server

An MCP (Model Context Protocol) server that provides automated AWS network architecture assessments, Direct Connect resiliency scoring, Transit Gateway topology analysis, and Cloud WAN discovery — using standard AWS SDK (boto3) APIs.

## What This Does

Gives AI agents direct access to AWS hybrid networking data for architecture reviews, troubleshooting, and migration planning. Covers Direct Connect, Transit Gateway, Cloud WAN, VPN, and VPC endpoints.

## How It Works

This server provides **structured data and resiliency scoring** — the AI agent provides the interpretation, recommendations, and formatted reports.

| Layer | Responsibility | Example Output |
|-------|---------------|----------------|
| MCP Server | Raw data, resiliency scoring, severity classification | `"resiliency_level": "LOW", "score": 0, "severity": "CRITICAL"` |
| AI Agent | Recommendations, prioritization, business context | "Add a second DX location at a different facility for redundancy" |

### Compatible MCP Clients

Any MCP-compatible client can use this server as a data source:

- [Kiro CLI / Kiro IDE](https://kiro.dev)
- [Claude Desktop](https://claude.ai/download)
- [Amazon Q Developer CLI](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line.html)
- [Cursor](https://cursor.sh)
- [VS Code + GitHub Copilot](https://code.visualstudio.com/)

## Tools (13)

| Tool | Description |
|------|-------------|
| `analyze_dx_topology` | Full DX topology: connections, VIFs, gateways, BGP status, resiliency |
| `check_dx_resiliency` | Resiliency assessment: location diversity, redundancy, BGP, MTU, MACsec |
| `get_bgp_status` | BGP peer status for all virtual interfaces |
| `get_dx_vif_details` | Detailed VIF config, BGP peers, route filter prefixes |
| `get_dx_gateway_details` | DX Gateway associations, allowed prefixes, VGW/TGW mappings |
| `get_dx_cloudwatch_metrics` | DX utilization, errors, light levels, connection state |
| `get_vpn_details` | VPN connections, tunnel status, BGP, accepted routes |
| `analyze_tgw_topology` | TGW details, attachments, route tables |
| `get_tgw_route_table_details` | Deep-dive: associations, propagations, and routes |
| `get_virtual_gateway_details` | VGW details and VPC attachments |
| `analyze_cloudwan_topology` | Cloud WAN global/core networks, attachments, peerings |
| `get_vpc_endpoints` | VPC endpoints summary with pattern detection |
| `network_architecture_summary` | Complete architecture discovery combining all layers |

## Quick Start

### Prerequisites

- Python 3.10+
- AWS credentials configured (via `~/.aws/credentials`, environment variables, or IAM role)
- IAM permissions for: `directconnect:Describe*`, `ec2:Describe*`, `ec2:Search*`, `ec2:Get*`, `networkmanager:Describe*`, `networkmanager:List*`

### Installation

```bash
git clone https://github.com/aws-samples/sample-aws-network-architecture-mcp-server.git
cd sample-aws-network-architecture-mcp-server
pip install -r requirements.txt
```

### Run

```bash
python server.py
```

### Configure with Claude Desktop / Kiro CLI

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "aws-network-architecture": {
      "command": "python",
      "args": ["/path/to/sample-aws-network-architecture-mcp-server/server.py"]
    }
  }
}
```

## Example Prompts

```
"Analyze the Direct Connect topology and score resiliency"
"Show me all TGW route tables with blackhole routes"
"What's the BGP status across all my virtual interfaces?"
"Give me a full network architecture summary"
"Check if my DX setup has location diversity"
"List all Cloud WAN attachments and their segments"
```

## Resiliency Scoring

The `check_dx_resiliency` tool scores across 5 dimensions:

| Check | Severity | Score Impact |
|-------|----------|--------------|
| Location Diversity (single location) | CRITICAL | -40 |
| Connection Redundancy (< 2 per location) | HIGH | -15 per location |
| BGP Health (peers down) | HIGH | -10 per peer |
| MTU Consistency (mixed values) | MEDIUM | -5 |
| MACsec (capable but not enabled) | MEDIUM | -5 |

Resiliency levels:
- **HIGH (Maximum Resiliency)**: 2+ locations, 2+ connections per location
- **MEDIUM (High Resiliency)**: 2+ locations, some with single connection
- **LOW (Single Location)**: All connections in one facility

## Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "directconnect:Describe*",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:GetTransitGatewayRouteTableAssociations",
        "ec2:GetTransitGatewayRouteTablePropagations",
        "ec2:SearchTransitGatewayRoutes",
        "ec2:DescribeVpnGateways",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcEndpoints",
        "networkmanager:DescribeGlobalNetworks",
        "networkmanager:ListCoreNetworks",
        "networkmanager:ListAttachments",
        "networkmanager:ListPeerings",
        "cloudwatch:GetMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

## Authentication

The server uses the standard AWS credential chain. Configure credentials using any of these methods:

### Option 1: AWS CLI Profile
```bash
aws configure --profile my-network-account
export AWS_PROFILE=my-network-account
python server.py
```

### Option 2: AWS IAM Identity Center (SSO)
```bash
aws sso login --profile my-sso-profile
export AWS_PROFILE=my-sso-profile
python server.py
```

### Option 3: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...       # if using temporary credentials
export AWS_DEFAULT_REGION=us-east-1
python server.py
```

### Option 4: IAM Role (EC2 / ECS / Lambda)
No configuration needed — credentials are auto-detected from the instance metadata service.

### MCP Client Configuration with Profile
```json
{
  "mcpServers": {
    "aws-network-architecture": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": {
        "AWS_PROFILE": "my-network-account",
        "AWS_DEFAULT_REGION": "us-east-1"
      }
    }
  }
}
```

> **Note:** The server defaults to `us-east-1` if no region is specified in tool calls. Each tool accepts a `region` parameter to query other regions.

## Architecture

```
┌─────────────────────────────────────┐
│         MCP Client (Claude/Kiro)    │
└──────────────────┬──────────────────┘
                   │ MCP Protocol (stdio)
┌──────────────────▼──────────────────┐
│   AWS Network Architecture Server   │
│         (FastMCP + boto3)           │
└──────────────────┬──────────────────┘
                   │ AWS SDK calls
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌────────┐  ┌──────────┐  ┌────────────┐
│Direct  │  │   EC2    │  │  Network   │
│Connect │  │(TGW/VPN/ │  │  Manager   │
│  API   │  │VPC/VGW)  │  │(Cloud WAN) │
└────────┘  └──────────┘  └────────────┘
```

## Security

### Defense in Depth

| Layer | Enforcement |
|-------|-------------|
| **Application** | All tools use only `Describe*`, `List*`, `Get*`, `Search*` calls |
| **IAM** (recommended) | Run with the [least-privilege role above](#required-iam-permissions) — not `AdministratorAccess` or broad `ReadOnlyAccess` |
| **SCP** (optional) | Deny `Create*`/`Delete*`/`Update*` on DX/TGW at the OU level |

> **Why this matters:** If a prompt injection tricks the AI client into calling a mutating API, the IAM role is your last line of defense. Scope credentials to only what the tools need.

- ✅ No mutations in code
- ✅ No data stored or exfiltrated
- ✅ No external dependencies beyond AWS APIs

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
