#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { fileURLToPath } from "url";
import path from "path";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from the project root (one directory up from /src or /dist)
dotenv.config({ path: path.join(__dirname, "..", ".env"), quiet: true });

import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { S3Client, ListBucketsCommand, GetBucketPolicyStatusCommand } from "@aws-sdk/client-s3";
import { EC2Client, DescribeInstancesCommand, DescribeSecurityGroupsCommand, DescribeAddressesCommand, DescribeVolumesCommand, DescribeVpcsCommand, DescribeSubnetsCommand, DescribeRouteTablesCommand, DescribeInternetGatewaysCommand, DescribeNatGatewaysCommand } from "@aws-sdk/client-ec2";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { IAMClient, ListUsersCommand, ListAccessKeysCommand, ListMFADevicesCommand } from "@aws-sdk/client-iam";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { CostExplorerClient, GetCostAndUsageCommand, GetCostForecastCommand, GetAnomaliesCommand, GetSavingsPlansUtilizationCommand, GetReservationUtilizationCommand } from "@aws-sdk/client-cost-explorer";
import { GuardDutyClient, ListFindingsCommand, GetFindingsCommand, ListDetectorsCommand } from "@aws-sdk/client-guardduty";
import { CloudWatchLogsClient, GetLogEventsCommand, DescribeLogStreamsCommand, FilterLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { HealthClient, DescribeEventsCommand } from "@aws-sdk/client-health";
import { ACMClient, ListCertificatesCommand, DescribeCertificateCommand } from "@aws-sdk/client-acm";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { BackupClient, ListBackupJobsCommand } from "@aws-sdk/client-backup";
import { BudgetsClient, DescribeBudgetsCommand } from "@aws-sdk/client-budgets";
import { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand, DescribeTargetGroupsCommand, DescribeTargetHealthCommand, DescribeListenersCommand, DescribeRulesCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { WAFV2Client, ListWebACLsCommand, GetSampledRequestsCommand, ListIPSetsCommand, GetIPSetCommand } from "@aws-sdk/client-wafv2";
import { SNSClient, ListTopicsCommand, ListSubscriptionsCommand } from "@aws-sdk/client-sns";
import { Route53Client, ListHostedZonesCommand, ListResourceRecordSetsCommand } from "@aws-sdk/client-route-53";
import { GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import { ECSClient, ListClustersCommand, ListServicesCommand, DescribeClustersCommand, DescribeServicesCommand } from "@aws-sdk/client-ecs";
import { EKSClient, ListClustersCommand as ListEksClustersCommand, DescribeClusterCommand } from "@aws-sdk/client-eks";
import { AutoScalingClient, DescribeAutoScalingGroupsCommand, DescribeScalingActivitiesCommand } from "@aws-sdk/client-auto-scaling";
import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { SecretsManagerClient, ListSecretsCommand } from "@aws-sdk/client-secrets-manager";
import { SSMClient, DescribeParametersCommand } from "@aws-sdk/client-ssm";
import { CloudFormationClient, ListStacksCommand } from "@aws-sdk/client-cloudformation";
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { SupportClient, DescribeTrustedAdvisorChecksCommand } from "@aws-sdk/client-support";
import checkIp from "ip-range-check";
import { z } from "zod";

// Initialize AWS Clients
// These will automatically pick up AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION from the environment
const s3Client = new S3Client({});
const ec2Client = new EC2Client({});
const stsClient = new STSClient({});
const iamClient = new IAMClient({});
const cloudTrailClient = new CloudTrailClient({});
const cloudWatchClient = new CloudWatchClient({});
const costExplorerClient = new CostExplorerClient({});
const guardDutyClient = new GuardDutyClient({});
const cloudWatchLogsClient = new CloudWatchLogsClient({});
const healthClient = new HealthClient({ region: "us-east-1" }); // AWS Health API is global (us-east-1)
const acmClient = new ACMClient({});
const rdsClient = new RDSClient({});
const lambdaClient = new LambdaClient({});
const backupClient = new BackupClient({});
const budgetsClient = new BudgetsClient({});
const elbv2Client = new ElasticLoadBalancingV2Client({});
const wafv2Client = new WAFV2Client({});
const snsClient = new SNSClient({});
const route53Client = new Route53Client({});
const ecsClient = new ECSClient({});
const eksClient = new EKSClient({});
const asgClient = new AutoScalingClient({});
const cloudFrontClient = new CloudFrontClient({});
const secretsManagerClient = new SecretsManagerClient({});
const ssmClient = new SSMClient({});
const cfnClient = new CloudFormationClient({});
const dynamoDbClient = new DynamoDBClient({});
const supportClient = new SupportClient({ region: "us-east-1" }); // AWS Support API is global (us-east-1)

const server = new Server(
    {
        name: "aws-mcp-server",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

// Define Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "get_aws_caller_identity",
                description: "Returns the AWS IAM caller identity (user/role) to verify credentials.",
                inputSchema: {
                    type: "object",
                    properties: {},
                },
            },
            {
                name: "list_s3_buckets",
                description: "Lists all S3 buckets in the AWS account.",
                inputSchema: {
                    type: "object",
                    properties: {
                        check_public_access: {
                            type: "boolean",
                            description: "If true, checks if buckets have public access enabled."
                        }
                    },
                },
            },
            {
                name: "list_ec2_instances",
                description: "Lists EC2 instances in the current region, showing ID, type, state, and public IP.",
                inputSchema: {
                    type: "object",
                    properties: {
                        region: {
                            type: "string",
                            description: "Optional AWS region to list instances from (overrides default)",
                        },
                    },
                },
            },
            {
                name: "list_iam_users",
                description: "Lists IAM users in the AWS account.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_recent_cloudtrail_events",
                description: "Lists recent CloudTrail events to track console access and changes.",
                inputSchema: {
                    type: "object",
                    properties: {
                        limit: {
                            type: "number",
                            description: "Number of events to return (default: 10).",
                        },
                        lookup_attribute_key: {
                            type: "string",
                            description: "Attribute key to filter by (e.g., 'EventName', 'Username')."
                        },
                        lookup_attribute_value: {
                            type: "string",
                            description: "Value for the lookup attribute."
                        }
                    }
                }
            },
            {
                name: "list_cloudwatch_alarms",
                description: "Lists CloudWatch alarms, optionally filtering by state.",
                inputSchema: {
                    type: "object",
                    properties: {
                        state: {
                            type: "string",
                            enum: ["OK", "ALARM", "INSUFFICIENT_DATA"],
                            description: "Filter alarms by state."
                        }
                    }
                }
            },
            {
                name: "get_recent_cost",
                description: "Retrieves daily AWS costs for the specified date range (default: last 7 days).",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: {
                            type: "string",
                            description: "Start date in YYYY-MM-DD format."
                        },
                        end_date: {
                            type: "string",
                            description: "End date in YYYY-MM-DD format."
                        }
                    }
                }
            },
            {
                name: "get_cost_by_service",
                description: "Retrieves AWS costs broken down by service for the specified date range.",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: {
                            type: "string",
                            description: "Start date in YYYY-MM-DD format."
                        },
                        end_date: {
                            type: "string",
                            description: "End date in YYYY-MM-DD format."
                        }
                    }
                }
            },
            {
                name: "get_cost_breakdown",
                description: "Detailed cost analysis. If service_name is provided, breaks down that service by Usage Type. Otherwise, breaks down by Service.",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: { type: "string", description: "Start date in YYYY-MM-DD format (default: 14 days ago)." },
                        end_date: { type: "string", description: "End date in YYYY-MM-DD format." },
                        service_name: { type: "string", description: "Optional: Specific service to analyze (e.g., 'Amazon Elastic Compute Cloud - Compute')." }
                    }
                }
            },
            {
                name: "get_cost_forecast",
                description: "Predicts future costs for a specified time range.",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: { type: "string", description: "Start date (YYYY-MM-DD)." },
                        end_date: { type: "string", description: "End date (YYYY-MM-DD)." },
                        granularity: { type: "string", enum: ["DAILY", "MONTHLY", "HOURLY"], description: "Granularity (default: DAILY)." },
                        prediction_interval_level: { type: "number", description: "Prediction interval confidence (51-99, default: 80)." }
                    },
                    required: ["start_date", "end_date"]
                }
            },
            {
                name: "get_budget_details",
                description: "Lists all AWS Budgets along with their status, limits, and current spend.",
                inputSchema: {
                    type: "object",
                    properties: {
                        account_id: { type: "string", description: "The AWS Account ID (required for Budgets)." }
                    },
                    required: ["account_id"]
                }
            },
            {
                name: "get_cost_anomalies",
                description: "Retrieves cost anomalies detected by AWS Cost Anomaly Detection.",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: { type: "string", description: "Start date (YYYY-MM-DD)." },
                        end_date: { type: "string", description: "End date (YYYY-MM-DD)." }
                    },
                    required: ["start_date", "end_date"]
                }
            },
            {
                name: "get_savings_plans_utilization",
                description: "Retrieves Savings Plans utilization percentages.",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: { type: "string", description: "Start date (YYYY-MM-DD)." },
                        end_date: { type: "string", description: "End date (YYYY-MM-DD)." }
                    },
                    required: ["start_date", "end_date"]
                }
            },
            {
                name: "get_reservation_utilization",
                description: "Retrieves Reserved Instance (RI) utilization percentages.",
                inputSchema: {
                    type: "object",
                    properties: {
                        start_date: { type: "string", description: "Start date (YYYY-MM-DD)." },
                        end_date: { type: "string", description: "End date (YYYY-MM-DD)." }
                    },
                    required: ["start_date", "end_date"]
                }
            },


            {
                name: "get_instance_details",
                description: "Retrieves detailed information about a specific EC2 instance.",
                inputSchema: {
                    type: "object",
                    properties: {
                        instance_id: { type: "string", description: "The ID of the EC2 instance." }
                    },
                    required: ["instance_id"]
                }
            },
            {
                name: "list_vpcs",
                description: "Lists all VPCs in the current region.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_subnets",
                description: "Lists subnets with availability zones and available IP counts.",
                inputSchema: {
                    type: "object",
                    properties: {
                        vpc_id: { type: "string", description: "Optional: Filter by VPC ID." }
                    }
                }
            },
            {
                name: "list_route_tables",
                description: "Lists route tables with their routes and associations.",
                inputSchema: {
                    type: "object",
                    properties: {
                        vpc_id: { type: "string", description: "Optional: Filter by VPC ID." }
                    }
                }
            },
            {
                name: "list_internet_gateways",
                description: "Lists Internet Gateways and their attachments.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_nat_gateways",
                description: "Lists NAT Gateways with their state and public IP.",
                inputSchema: {
                    type: "object",
                    properties: {
                        vpc_id: { type: "string", description: "Optional: Filter by VPC ID." }
                    }
                }
            },
            {
                name: "list_security_groups",
                description: "Lists all security groups.",
                inputSchema: {
                    type: "object",
                    properties: {
                        vpc_id: { type: "string", description: "Optional: Filter by VPC ID." }
                    }
                }
            },
            {
                name: "list_users_without_mfa",
                description: "Lists IAM users who do not have MFA enabled.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_old_access_keys",
                description: "Lists access keys older than 90 days (or specified days).",
                inputSchema: {
                    type: "object",
                    properties: {
                        days: {
                            type: "number",
                            description: "Number of days threshold (default: 90)."
                        }
                    }
                }
            },
            {
                name: "list_expiring_certificates",
                description: "Lists ACM certificates expiring within the specified days.",
                inputSchema: {
                    type: "object",
                    properties: {
                        days: {
                            type: "number",
                            description: "Number of days threshold (default: 30)."
                        }
                    }
                }
            },
            {
                name: "list_rds_instances",
                description: "Lists RDS instances with engine versions and status.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_lambda_functions",
                description: "Lists Lambda functions with runtimes and last modified dates.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_backup_jobs",
                description: "Lists recent backup jobs, optionally filtering by state (default: FAILED).",
                inputSchema: {
                    type: "object",
                    properties: {
                        state: {
                            type: "string",
                            description: "Filter by job state (e.g., COMPLETED, FAILED, RUNNING). Default: FAILED."
                        },
                        hours: {
                            type: "number",
                            description: "Look back window in hours (default: 24)."
                        }
                    }
                }
            },
            {
                name: "list_open_security_groups",
                description: "Lists security groups that allow ingress from 0.0.0.0/0 on specified ports (default: 22, 3389).",
                inputSchema: {
                    type: "object",
                    properties: {
                        ports: {
                            type: "array",
                            items: { type: "number" },
                            description: "List of ports to check (default: [22, 3389])."
                        }
                    }
                }
            },
            {
                name: "list_unused_ebs_volumes",
                description: "Lists EBS volumes that are available (not attached to any instance).",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_unassociated_eips",
                description: "Lists Elastic IPs that are not associated with any instance.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_guardduty_findings",
                description: "Lists recent high-severity GuardDuty findings.",
                inputSchema: {
                    type: "object",
                    properties: {
                        severity: {
                            type: "number",
                            description: "Minimum severity level (default: 4)."
                        },
                        limit: {
                            type: "number",
                            description: "Number of findings to return (default: 10)."
                        }
                    }
                }
            },
            {
                name: "get_recent_logs",
                description: "Retrieves recent log events from a CloudWatch Log Group.",
                inputSchema: {
                    type: "object",
                    properties: {
                        log_group_name: {
                            type: "string",
                            description: "Name of the Log Group."
                        },
                        limit: {
                            type: "number",
                            description: "Number of log events to return (default: 20)."
                        }
                    },
                    required: ["log_group_name"]
                }
            },
            {
                name: "search_cloudwatch_logs",
                description: "Search CloudWatch logs using a filter pattern (e.g., 'ERROR', 'Exception').",
                inputSchema: {
                    type: "object",
                    properties: {
                        log_group_name: {
                            type: "string",
                            description: "Name of the Log Group."
                        },
                        filter_pattern: {
                            type: "string",
                            description: "The filter pattern to use (e.g., 'ERROR', '{ $.latency > 100 }')."
                        },
                        limit: {
                            type: "number",
                            description: "Number of events to return (default: 50)."
                        },
                        hours: {
                            type: "number",
                            description: "Time window in hours (default: 24)."
                        },
                        start_time: { type: "string" },
                        end_time: { type: "string" }
                    },
                    required: ["log_group_name", "filter_pattern"]
                }
            },
            {
                name: "list_cloudtrail_changes",
                description: "Lists write/mutation events (Create, Update, Delete) for a specific resource or service.",
                inputSchema: {
                    type: "object",
                    properties: {
                        resource_id: {
                            type: "string",
                            description: "Optional: The Resource ID or Name (e.g., sg-12345, my-bucket)."
                        },
                        lookup_key: {
                            type: "string",
                            enum: ["ResourceName", "ResourceType", "EventName", "Username"],
                            description: "The attribute to lookup by (default: ResourceName if resource_id provided)."
                        },
                        lookup_value: {
                            type: "string",
                            description: "The value for the lookup key (required if resource_id is omitted)."
                        },
                        days: {
                            type: "number",
                            description: "Lookback period in days (default: 7)."
                        }
                    }
                }
            },
            {
                name: "list_access_denied_events",
                description: "Lists recent Access Denied or Unauthorized events from CloudTrail.",
                inputSchema: {
                    type: "object",
                    properties: {
                        limit: {
                            type: "number",
                            description: "Number of events to return (default: 20)."
                        }
                    }
                }
            },
            {
                name: "get_service_health",
                description: "Lists recent open events from AWS Health Dashboard.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_load_balancers",
                description: "Lists all Application and Network Load Balancers.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_target_groups",
                description: "Lists all Target Groups.",
                inputSchema: {
                    type: "object",
                    properties: {
                        load_balancer_arn: {
                            type: "string",
                            description: "Optional: Filter by Load Balancer ARN."
                        }
                    }
                }
            },
            {
                name: "list_listener_rules",
                description: "Lists listeners and routing rules (host, path) for a specified Load Balancer.",
                inputSchema: {
                    type: "object",
                    properties: {
                        load_balancer_arn: {
                            type: "string",
                            description: "The ARN of the Load Balancer."
                        }
                    },
                    required: ["load_balancer_arn"]
                }
            },
            {
                name: "get_target_health",
                description: "Retrieves the health of targets in a specified Target Group.",
                inputSchema: {
                    type: "object",
                    properties: {
                        target_group_arn: {
                            type: "string",
                            description: "The ARN of the Target Group."
                        }
                    },
                    required: ["target_group_arn"]
                }
            },
            {
                name: "list_web_acls",
                description: "Lists Web ACLs (Global/CloudFront or Regional).",
                inputSchema: {
                    type: "object",
                    properties: {
                        scope: {
                            type: "string",
                            enum: ["CLOUDFRONT", "REGIONAL"],
                            description: "The scope of the Web ACLs (default: REGIONAL)."
                        }
                    }
                }
            },
            {
                name: "get_waf_sampled_requests",
                description: "Retrieves sampled requests from a Web ACL.",
                inputSchema: {
                    type: "object",
                    properties: {
                        web_acl_arn: {
                            type: "string",
                            description: "The ARN of the Web ACL."
                        },
                        rule_metric_name: {
                            type: "string",
                            description: "The metric name of the rule to sample."
                        },
                        scope: {
                            type: "string",
                            enum: ["CLOUDFRONT", "REGIONAL"],
                            description: "The scope (default: REGIONAL)."
                        },
                        time_window_seconds: {
                            type: "number",
                            description: "Time window in seconds (e.g., 3600 for 1 hour)."
                        }
                    },
                    required: ["web_acl_arn", "rule_metric_name"]
                }
            },
            {
                name: "check_ip_in_waf",
                description: "Checks if an IP address exists in any WAF IP Set (Blocklists/Allowlists).",
                inputSchema: {
                    type: "object",
                    properties: {
                        ip_address: {
                            type: "string",
                            description: "The IP address to check (e.g., 192.168.1.1)."
                        }
                    },
                    required: ["ip_address"]
                }
            },
            {
                name: "get_metric_statistics",
                description: "Retrieves statistics for a specific CloudWatch metric.",
                inputSchema: {
                    type: "object",
                    properties: {
                        namespace: { type: "string", description: "The namespace of the metric (e.g., AWS/EC2)." },
                        metric_name: { type: "string", description: "The name of the metric (e.g., CPUUtilization)." },
                        dimensions: {
                            type: "array",
                            items: {
                                type: "object",
                                properties: { Name: { type: "string" }, Value: { type: "string" } }
                            },
                            description: "Array of dimensions (e.g., [{Name: 'InstanceId', Value: 'i-xxx'}])."
                        },
                        start_time: { type: "string", description: "Start time (ISO string)." },
                        end_time: { type: "string", description: "End time (ISO string)." },
                        period: { type: "number", description: "Granularity in seconds (default: 300)." },
                        statistics: { type: "array", items: { type: "string" }, description: "Statistics to retrieve (e.g., ['Average', 'Maximum'])." }
                    },
                    required: ["namespace", "metric_name"]
                }
            },
            {
                name: "list_sns_topics",
                description: "Lists all SNS topics.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_record_sets",
                description: "Lists DNS records for a given hosted zone.",
                inputSchema: {
                    type: "object",
                    properties: {
                        hosted_zone_id: {
                            type: "string",
                            description: "The ID of the Hosted Zone."
                        }
                    },
                    required: ["hosted_zone_id"]
                }
            },
            {
                name: "list_hosted_zones",
                description: "Lists all Route53 Hosted Zones.",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "list_ecs_clusters",
                description: "Lists ECS clusters with their status and running task counts.",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_ecs_services",
                description: "Lists services in a specific ECS cluster.",
                inputSchema: {
                    type: "object",
                    properties: {
                        cluster: { "type": "string", "description": "The name or ARN of the ECS cluster." }
                    },
                    required: ["cluster"]
                }
            },
            {
                name: "list_eks_clusters",
                description: "Lists EKS clusters in the current region.",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_auto_scaling_groups",
                description: "Lists Auto Scaling Groups with their capacity settings.",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_scaling_activities",
                description: "Describes recent scaling activities for an Auto Scaling Group.",
                inputSchema: {
                    type: "object",
                    properties: {
                        auto_scaling_group_name: { "type": "string", "description": "The name of the Auto Scaling Group." }
                    },
                    required: ["auto_scaling_group_name"]
                }
            },
            {
                name: "list_cloudfront_distributions",
                description: "Lists CloudFront distributions with their domain names and status.",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_secrets",
                description: "Lists Secrets Manager secrets (names only).",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_ssm_parameters",
                description: "Lists SSM Parameters (names only).",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_cloudformation_stacks",
                description: "Lists CloudFormation stacks and their status.",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_dynamodb_tables",
                description: "Lists DynamoDB tables.",
                inputSchema: { "type": "object", "properties": {} }
            },
            {
                name: "list_trusted_advisor_checks",
                description: "Lists Trusted Advisor checks available.",
                inputSchema: { "type": "object", "properties": {} }
            }
        ]
    };
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        if (name === "get_aws_caller_identity") {
            const command = new GetCallerIdentityCommand({});
            const response = await stsClient.send(command);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(
                            {
                                UserId: response.UserId,
                                Account: response.Account,
                                Arn: response.Arn,
                            },
                            null,
                            2
                        ),
                    },
                ],
            };
        }

        if (name === "list_s3_buckets") {
            const command = new ListBucketsCommand({});
            const response = await s3Client.send(command);

            let buckets = response.Buckets?.map((b) => ({
                Name: b.Name,
                CreationDate: b.CreationDate,
                IsPublic: undefined as boolean | undefined
            })) || [];

            if (args && (args as any).check_public_access) {
                buckets = await Promise.all(buckets.map(async (b) => {
                    try {
                        if (!b.Name) return b;
                        const policyCmd = new GetBucketPolicyStatusCommand({ Bucket: b.Name });
                        const policyResponse = await s3Client.send(policyCmd);
                        return { ...b, IsPublic: policyResponse.PolicyStatus?.IsPublic || false };
                    } catch (error) {
                        // If checks fail (e.g. AccessDenied or no policy context), assume not public or unknown
                        return { ...b, IsPublic: false };
                    }
                }));
            }

            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(buckets, null, 2),
                    },
                ],
            };
        }

        if (name === "list_ec2_instances") {
            // Create a region-specific client if provided, otherwise use default
            // Note: Re-instantiating client for every request isn't ideal for perf but fine for this scale
            // To strictly support region override we'd need to recreate the client or default to the global one
            // For simplicity here using the global one unless specific tool logic is needed.
            // Actually, if args.region is passed, we should use a new client.

            const region = (args as { region?: string })?.region;
            const client = region ? new EC2Client({ region }) : ec2Client;

            const command = new DescribeInstancesCommand({});
            const response = await client.send(command);

            const instances = response.Reservations?.flatMap(
                (r) =>
                    r.Instances?.map((i) => ({
                        InstanceId: i.InstanceId,
                        Name: i.Tags?.find((t) => t.Key === "Name")?.Value,
                        InstanceType: i.InstanceType,
                        State: i.State?.Name,
                        PublicIpAddress: i.PublicIpAddress,
                        PrivateIpAddress: i.PrivateIpAddress,
                        LaunchTime: i.LaunchTime,
                        Tags: i.Tags,
                    })) || []
            ) || [];

            const content: any[] = [
                {
                    type: "text",
                    text: JSON.stringify(instances, null, 2),
                }
            ];

            if (!region) {
                content.push({
                    type: "text",
                    text: "\n(Checked default region 'us-east-1'. Use the 'region' argument to check other regions like 'ap-south-1', 'us-west-2', etc.)"
                });
            }

            return {
                content: content,
            };
        }

        if (name === "list_iam_users") {
            const command = new ListUsersCommand({});
            const response = await iamClient.send(command);
            const users = response.Users?.map(u => ({
                UserName: u.UserName,
                UserId: u.UserId,
                Arn: u.Arn,
                CreateDate: u.CreateDate
            })) || [];

            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(users, null, 2)
                    }
                ]
            }
        }

        if (name === "list_recent_cloudtrail_events") {
            const limit = (args as any)?.limit || 10;
            const lookupKey = (args as any)?.lookup_attribute_key;
            const lookupValue = (args as any)?.lookup_attribute_value;

            const commandInput: any = { MaxResults: limit };
            if (lookupKey && lookupValue) {
                commandInput.LookupAttributes = [{ AttributeKey: lookupKey, AttributeValue: lookupValue }];
            }

            const command = new LookupEventsCommand(commandInput);
            const response = await cloudTrailClient.send(command);

            const events = response.Events?.map(e => ({
                EventId: e.EventId,
                EventName: e.EventName,
                EventTime: e.EventTime,
                Username: e.Username,
                Resources: e.Resources,
                CloudTrailEvent: e.CloudTrailEvent ? JSON.parse(e.CloudTrailEvent).userAgent : undefined // Extract user agent if available
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(events, null, 2) }]
            };
        }

        if (name === "list_cloudwatch_alarms") {
            const state = (args as any)?.state;
            const commandInput: any = {};
            if (state) commandInput.StateValue = state;

            const command = new DescribeAlarmsCommand(commandInput);
            const response = await cloudWatchClient.send(command);

            const alarms = response.MetricAlarms?.map(a => ({
                AlarmName: a.AlarmName,
                StateValue: a.StateValue,
                StateReason: a.StateReason,
                MetricName: a.MetricName,
                Namespace: a.Namespace
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(alarms, null, 2) }]
            };
        }

        if (name === "get_recent_cost") {
            const endDate = (args as any)?.end_date || new Date().toISOString().split('T')[0];
            const startDate = (args as any)?.start_date || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

            const command = new GetCostAndUsageCommand({
                TimePeriod: { Start: startDate, End: endDate },
                Granularity: "DAILY",
                Metrics: ["UnblendedCost"]
            });
            const response = await costExplorerClient.send(command);

            const costs = response.ResultsByTime?.map(r => ({
                TimePeriod: r.TimePeriod,
                Total: r.Total?.UnblendedCost
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(costs, null, 2) }]
            };
        }

        if (name === "get_cost_by_service") {
            const endDate = (args as any)?.end_date || new Date().toISOString().split('T')[0];
            const startDate = (args as any)?.start_date || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

            const command = new GetCostAndUsageCommand({
                TimePeriod: { Start: startDate, End: endDate },
                Granularity: "DAILY",
                Metrics: ["UnblendedCost"],
                GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }]
            });
            const response = await costExplorerClient.send(command);

            const costs = response.ResultsByTime?.flatMap(r =>
                r.Groups?.map(g => ({
                    Date: r.TimePeriod?.Start,
                    Service: g.Keys?.[0],
                    Cost: g.Metrics?.UnblendedCost?.Amount,
                    Unit: g.Metrics?.UnblendedCost?.Unit
                }))
            ) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(costs, null, 2) }]
            };
        }

        if (name === "get_cost_breakdown") {
            const endDate = (args as any)?.end_date || new Date().toISOString().split('T')[0];
            const startDate = (args as any)?.start_date || new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
            const serviceName = (args as any)?.service_name;

            const groupByKey = serviceName ? "USAGE_TYPE" : "SERVICE";
            const filter = serviceName
                ? { Dimensions: { Key: "SERVICE", Values: [serviceName] } } as any
                : undefined;

            const command = new GetCostAndUsageCommand({
                TimePeriod: { Start: startDate, End: endDate },
                Granularity: "DAILY",
                Metrics: ["UnblendedCost"],
                GroupBy: [{ Type: "DIMENSION", Key: groupByKey }],
                Filter: filter
            });

            const response = await costExplorerClient.send(command);

            const costs = response.ResultsByTime?.flatMap(r =>
                r.Groups?.map(g => ({
                    Date: r.TimePeriod?.Start,
                    [groupByKey === "USAGE_TYPE" ? "UsageType" : "Service"]: g.Keys?.[0],
                    Cost: parseFloat(g.Metrics?.UnblendedCost?.Amount || "0").toFixed(4),
                    Unit: g.Metrics?.UnblendedCost?.Unit
                }))
            )
                .filter(c => c && parseFloat(c.Cost) > 0) // Filter out zero costs
                .sort((a, b) => parseFloat(b?.Cost || "0") - parseFloat(a?.Cost || "0")) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(costs.slice(0, 100), null, 2) }]
            };
        }

        if (name === "get_cost_forecast") {
            const command = new GetCostForecastCommand({
                TimePeriod: { Start: (args as any).start_date, End: (args as any).end_date },
                Granularity: (args as any)?.granularity || "DAILY",
                Metric: "UNBLENDED_COST",
                PredictionIntervalLevel: (args as any)?.prediction_interval_level || 80
            });
            const response = await costExplorerClient.send(command);

            const forecast = response.ForecastResultsByTime?.map(f => ({
                Date: f.TimePeriod?.Start,
                MeanValue: f.MeanValue,
                PredictionIntervalLower: f.PredictionIntervalLowerBound,
                PredictionIntervalUpper: f.PredictionIntervalUpperBound
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify({ Total: response.Total, Forecast: forecast }, null, 2) }] };
        }

        if (name === "get_budget_details") {
            const accountId = (args as any).account_id;
            const command = new DescribeBudgetsCommand({ AccountId: accountId, MaxResults: 100 });
            const response = await budgetsClient.send(command);

            const budgets = response.Budgets?.map(b => ({
                BudgetName: b.BudgetName,
                Limit: b.BudgetLimit?.Amount + " " + b.BudgetLimit?.Unit,
                CurrentSpend: b.CalculatedSpend?.ActualSpend?.Amount + " " + b.CalculatedSpend?.ActualSpend?.Unit,
                ForecastedSpend: b.CalculatedSpend?.ForecastedSpend?.Amount + " " + b.CalculatedSpend?.ForecastedSpend?.Unit,
                BudgetType: b.BudgetType,
                LastUpdated: b.LastUpdatedTime
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(budgets, null, 2) }] };
        }

        if (name === "get_cost_anomalies") {
            const command = new GetAnomaliesCommand({
                DateInterval: { StartDate: (args as any).start_date, EndDate: (args as any).end_date },
                MaxResults: 20
            });
            const response = await costExplorerClient.send(command);

            const anomalies = response.Anomalies?.map(a => ({
                AnomalyId: a.AnomalyId,
                AnomalyScore: a.AnomalyScore,
                ImpactTotal: a.Impact?.TotalImpact,
                MonitorArn: a.MonitorArn,
                RootCauses: a.RootCauses,
                Date: a.AnomalyEndDate
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(anomalies, null, 2) }] };
        }

        if (name === "get_savings_plans_utilization") {
            const command = new GetSavingsPlansUtilizationCommand({
                TimePeriod: { Start: (args as any).start_date, End: (args as any).end_date }
            });
            const response = await costExplorerClient.send(command);

            const utils = response.SavingsPlansUtilizationsByTime?.map(u => ({
                Date: u.TimePeriod?.Start,
                UtilizationPercentage: u.Utilization?.UtilizationPercentage + "%",
                TotalCommitment: u.Utilization?.TotalCommitment,
                UsedCommitment: u.Utilization?.UsedCommitment,
                UnusedCommitment: u.Utilization?.UnusedCommitment
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(utils, null, 2) }] };
        }

        if (name === "get_reservation_utilization") {
            const command = new GetReservationUtilizationCommand({
                TimePeriod: { Start: (args as any).start_date, End: (args as any).end_date }
            });
            const response = await costExplorerClient.send(command);

            const utils = response.UtilizationsByTime?.map(u => ({
                Date: u.TimePeriod?.Start,
                TotalPotentialRIHours: u.Total?.TotalPotentialRISavings, // Approximate proxy if direct hours not shown in all interfaces
                UtilizationPercentage: u.Total?.UtilizationPercentage + "%",
                PurchasedUnits: u.Total?.PurchasedHours,
                TotalActualHours: u.Total?.TotalActualHours,
                UnusedHours: u.Total?.UnusedHours
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(utils, null, 2) }] };
        }

        if (name === "list_users_without_mfa") {
            const listCmd = new ListUsersCommand({});
            const listResp = await iamClient.send(listCmd);
            const users = listResp.Users || [];

            const noMfaUsers = [];

            // Checking users sequentially to avoid rate limiting
            for (const user of users) {
                if (!user.UserName) continue;
                try {
                    const mfaCmd = new ListMFADevicesCommand({ UserName: user.UserName });
                    const mfaResp = await iamClient.send(mfaCmd);
                    if (!mfaResp.MFADevices || mfaResp.MFADevices.length === 0) {
                        noMfaUsers.push({
                            UserName: user.UserName,
                            UserId: user.UserId,
                            CreateDate: user.CreateDate,
                            PasswordLastUsed: user.PasswordLastUsed
                        });
                    }
                } catch (err) {
                    // Ignore errors (e.g. AccessDenied)
                }
            }

            return {
                content: [{ type: "text", text: JSON.stringify(noMfaUsers, null, 2) }]
            };
        }

        if (name === "list_old_access_keys") {
            const days = (args as any)?.days || 90;
            const thresholdDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

            const listCmd = new ListUsersCommand({});
            const listResp = await iamClient.send(listCmd);
            const users = listResp.Users || [];

            const oldKeys = [];

            for (const user of users) {
                if (!user.UserName) continue;
                try {
                    const keysCmd = new ListAccessKeysCommand({ UserName: user.UserName });
                    const keysResp = await iamClient.send(keysCmd);

                    if (keysResp.AccessKeyMetadata) {
                        for (const key of keysResp.AccessKeyMetadata) {
                            if (key.CreateDate && key.CreateDate < thresholdDate && key.Status === "Active") {
                                oldKeys.push({
                                    UserName: user.UserName,
                                    AccessKeyId: key.AccessKeyId,
                                    CreateDate: key.CreateDate,
                                    Status: key.Status,
                                    DaysOld: Math.floor((Date.now() - key.CreateDate.getTime()) / (1000 * 60 * 60 * 24))
                                });
                            }
                        }
                    }
                } catch (err) {
                    // Ignore
                }
            }

            return {
                content: [{ type: "text", text: JSON.stringify(oldKeys, null, 2) }]
            };
        }

        if (name === "list_expiring_certificates") {
            const days = (args as any)?.days || 30;
            const thresholdDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

            const listCmd = new ListCertificatesCommand({});
            const listResp = await acmClient.send(listCmd); // Note: paginates 1000 by default

            const expiringCerts = [];

            // We need to describe to get 'NotAfter'
            for (const certSummary of listResp.CertificateSummaryList || []) {
                if (!certSummary.CertificateArn) continue;
                try {
                    const descCmd = new DescribeCertificateCommand({ CertificateArn: certSummary.CertificateArn });
                    const descResp = await acmClient.send(descCmd);
                    const cert = descResp.Certificate;

                    if (cert && cert.NotAfter && cert.NotAfter < thresholdDate) {
                        expiringCerts.push({
                            DomainName: cert.DomainName,
                            CertificateArn: cert.CertificateArn,
                            NotAfter: cert.NotAfter,
                            Status: cert.Status,
                            InUseBy: cert.InUseBy
                        });
                    }
                } catch (err) {
                    // Ignore
                }
            }

            return {
                content: [{ type: "text", text: JSON.stringify(expiringCerts, null, 2) }]
            };
        }

        if (name === "list_rds_instances") {
            const command = new DescribeDBInstancesCommand({});
            const response = await rdsClient.send(command);

            const instances = response.DBInstances?.map(db => ({
                DBInstanceIdentifier: db.DBInstanceIdentifier,
                Engine: db.Engine,
                EngineVersion: db.EngineVersion,
                DBInstanceClass: db.DBInstanceClass,
                DBInstanceStatus: db.DBInstanceStatus,
                Endpoint: db.Endpoint?.Address
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(instances, null, 2) }]
            };
        }

        if (name === "list_lambda_functions") {
            const command = new ListFunctionsCommand({});
            const response = await lambdaClient.send(command);

            const funcs = response.Functions?.map(f => ({
                FunctionName: f.FunctionName,
                Runtime: f.Runtime,
                LastModified: f.LastModified,
                Handler: f.Handler,
                CodeSize: f.CodeSize
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(funcs, null, 2) }]
            };
        }

        if (name === "list_backup_jobs") {
            const state = (args as any)?.state || "FAILED";
            const hours = (args as any)?.hours || 24;
            const sinceDate = new Date(Date.now() - hours * 60 * 60 * 1000);

            const command = new ListBackupJobsCommand({
                ByState: state,
                ByCreatedAfter: sinceDate
            });
            const response = await backupClient.send(command);

            const jobs = response.BackupJobs?.map(j => ({
                BackupJobId: j.BackupJobId,
                State: j.State,
                CreationDate: j.CreationDate,
                BackupVaultName: j.BackupVaultName,
                ResourceArn: j.ResourceArn,
                StatusMessage: j.StatusMessage
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(jobs, null, 2) }]
            };
        }

        if (name === "get_cost_by_service") {
            const endDate = (args as any)?.end_date || new Date().toISOString().split('T')[0];
            const startDate = (args as any)?.start_date || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

            const command = new GetCostAndUsageCommand({
                TimePeriod: { Start: startDate, End: endDate },
                Granularity: "DAILY",
                Metrics: ["UnblendedCost"],
                GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }]
            });
            const response = await costExplorerClient.send(command);

            const costs = response.ResultsByTime?.flatMap(r =>
                r.Groups?.map(g => ({
                    Date: r.TimePeriod?.Start,
                    Service: g.Keys?.[0],
                    Cost: g.Metrics?.UnblendedCost?.Amount,
                    Unit: g.Metrics?.UnblendedCost?.Unit
                }))
            ) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(costs, null, 2) }]
            };
        }




        if (name === "get_instance_details") {
            const instanceId = (args as any).instance_id;
            const command = new DescribeInstancesCommand({ InstanceIds: [instanceId] });
            const response = await ec2Client.send(command);

            const instance = response.Reservations?.[0]?.Instances?.[0];

            if (!instance) {
                return { content: [{ type: "text", text: "Instance not found." }] };
            }

            return { content: [{ type: "text", text: JSON.stringify(instance, null, 2) }] };
        }

        if (name === "list_vpcs") {
            const command = new DescribeVpcsCommand({});
            const response = await ec2Client.send(command);

            const vpcs = response.Vpcs?.map(v => ({
                VpcId: v.VpcId,
                CidrBlock: v.CidrBlock,
                IsDefault: v.IsDefault,
                State: v.State,
                Name: v.Tags?.find(t => t.Key === "Name")?.Value
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(vpcs, null, 2) }] };
        }

        if (name === "list_subnets") {
            const vpcId = (args as any)?.vpc_id;
            const input: any = {};
            if (vpcId) input.Filters = [{ Name: "vpc-id", Values: [vpcId] }];

            const command = new DescribeSubnetsCommand(input);
            const response = await ec2Client.send(command);

            const subnets = response.Subnets?.map(s => ({
                SubnetId: s.SubnetId,
                VpcId: s.VpcId,
                AvailabilityZone: s.AvailabilityZone,
                CidrBlock: s.CidrBlock,
                AvailableIpAddressCount: s.AvailableIpAddressCount,
                Name: s.Tags?.find(t => t.Key === "Name")?.Value
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(subnets, null, 2) }] };
        }

        if (name === "list_route_tables") {
            const vpcId = (args as any)?.vpc_id;
            const input: any = {};
            if (vpcId) input.Filters = [{ Name: "vpc-id", Values: [vpcId] }];

            const command = new DescribeRouteTablesCommand(input);
            const response = await ec2Client.send(command);

            const routeTables = response.RouteTables?.map(rt => ({
                RouteTableId: rt.RouteTableId,
                VpcId: rt.VpcId,
                Routes: rt.Routes?.map(r => ({
                    DestinationCidrBlock: r.DestinationCidrBlock,
                    GatewayId: r.GatewayId,
                    NatGatewayId: r.NatGatewayId,
                    State: r.State
                })),
                Associations: rt.Associations?.map(a => ({
                    RouteTableAssociationId: a.RouteTableAssociationId,
                    SubnetId: a.SubnetId,
                    Main: a.Main
                })),
                Name: rt.Tags?.find(t => t.Key === "Name")?.Value
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(routeTables, null, 2) }] };
        }

        if (name === "list_internet_gateways") {
            const command = new DescribeInternetGatewaysCommand({});
            const response = await ec2Client.send(command);

            const igws = response.InternetGateways?.map(igw => ({
                InternetGatewayId: igw.InternetGatewayId,
                Attachments: igw.Attachments,
                Name: igw.Tags?.find(t => t.Key === "Name")?.Value
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(igws, null, 2) }] };
        }

        if (name === "list_nat_gateways") {
            const vpcId = (args as any)?.vpc_id;
            const input: any = {};
            if (vpcId) input.Filter = [{ Name: "vpc-id", Values: [vpcId] }];

            const command = new DescribeNatGatewaysCommand(input);
            const response = await ec2Client.send(command);

            const nats = response.NatGateways?.map(nat => ({
                NatGatewayId: nat.NatGatewayId,
                VpcId: nat.VpcId,
                SubnetId: nat.SubnetId,
                State: nat.State,
                PublicIp: nat.NatGatewayAddresses?.[0]?.PublicIp,
                Name: nat.Tags?.find(t => t.Key === "Name")?.Value
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(nats, null, 2) }] };
        }

        if (name === "list_security_groups") {
            const vpcId = (args as any)?.vpc_id;
            const filter = vpcId ? [{ Name: "vpc-id", Values: [vpcId] }] : undefined;

            const command = new DescribeSecurityGroupsCommand({ Filters: filter });
            const response = await ec2Client.send(command);

            const sgs = response.SecurityGroups?.map(s => ({
                GroupId: s.GroupId,
                GroupName: s.GroupName,
                Description: s.Description,
                VpcId: s.VpcId
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(sgs, null, 2) }] };
        }
        if (name === "list_users_without_mfa") {
            const listCmd = new ListUsersCommand({});
            const listResp = await iamClient.send(listCmd);
            const users = listResp.Users || [];

            const noMfaUsers = [];

            // Checking users sequentially to avoid rate limiting
            for (const user of users) {
                if (!user.UserName) continue;
                try {
                    const mfaCmd = new ListMFADevicesCommand({ UserName: user.UserName });
                    const mfaResp = await iamClient.send(mfaCmd);
                    if (!mfaResp.MFADevices || mfaResp.MFADevices.length === 0) {
                        noMfaUsers.push({
                            UserName: user.UserName,
                            UserId: user.UserId,
                            CreateDate: user.CreateDate,
                            PasswordLastUsed: user.PasswordLastUsed
                        });
                    }
                } catch (err) {
                    // Ignore errors (e.g. AccessDenied)
                }
            }

            return {
                content: [{ type: "text", text: JSON.stringify(noMfaUsers, null, 2) }]
            };
        }

        if (name === "list_old_access_keys") {
            const days = (args as any)?.days || 90;
            const thresholdDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

            const listCmd = new ListUsersCommand({});
            const listResp = await iamClient.send(listCmd);
            const users = listResp.Users || [];

            const oldKeys = [];

            for (const user of users) {
                if (!user.UserName) continue;
                try {
                    const keysCmd = new ListAccessKeysCommand({ UserName: user.UserName });
                    const keysResp = await iamClient.send(keysCmd);

                    if (keysResp.AccessKeyMetadata) {
                        for (const key of keysResp.AccessKeyMetadata) {
                            if (key.CreateDate && key.CreateDate < thresholdDate && key.Status === "Active") {
                                oldKeys.push({
                                    UserName: user.UserName,
                                    AccessKeyId: key.AccessKeyId,
                                    CreateDate: key.CreateDate,
                                    Status: key.Status,
                                    DaysOld: Math.floor((Date.now() - key.CreateDate.getTime()) / (1000 * 60 * 60 * 24))
                                });
                            }
                        }
                    }
                } catch (err) {
                    // Ignore
                }
            }

            return {
                content: [{ type: "text", text: JSON.stringify(oldKeys, null, 2) }]
            };
        }

        if (name === "list_expiring_certificates") {
            const days = (args as any)?.days || 30;
            const thresholdDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

            const listCmd = new ListCertificatesCommand({});
            const listResp = await acmClient.send(listCmd); // Note: paginates 1000 by default

            const expiringCerts = [];

            // We need to describe to get 'NotAfter'
            for (const certSummary of listResp.CertificateSummaryList || []) {
                if (!certSummary.CertificateArn) continue;
                try {
                    const descCmd = new DescribeCertificateCommand({ CertificateArn: certSummary.CertificateArn });
                    const descResp = await acmClient.send(descCmd);
                    const cert = descResp.Certificate;

                    if (cert && cert.NotAfter && cert.NotAfter < thresholdDate) {
                        expiringCerts.push({
                            DomainName: cert.DomainName,
                            CertificateArn: cert.CertificateArn,
                            NotAfter: cert.NotAfter,
                            Status: cert.Status,
                            InUseBy: cert.InUseBy
                        });
                    }
                } catch (err) {
                    // Ignore
                }
            }

            return {
                content: [{ type: "text", text: JSON.stringify(expiringCerts, null, 2) }]
            };
        }

        if (name === "list_rds_instances") {
            const command = new DescribeDBInstancesCommand({});
            const response = await rdsClient.send(command);

            const instances = response.DBInstances?.map(db => ({
                DBInstanceIdentifier: db.DBInstanceIdentifier,
                Engine: db.Engine,
                EngineVersion: db.EngineVersion,
                DBInstanceClass: db.DBInstanceClass,
                DBInstanceStatus: db.DBInstanceStatus,
                Endpoint: db.Endpoint?.Address
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(instances, null, 2) }]
            };
        }

        if (name === "list_lambda_functions") {
            const command = new ListFunctionsCommand({});
            const response = await lambdaClient.send(command);

            const funcs = response.Functions?.map(f => ({
                FunctionName: f.FunctionName,
                Runtime: f.Runtime,
                LastModified: f.LastModified,
                Handler: f.Handler,
                CodeSize: f.CodeSize
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(funcs, null, 2) }]
            };
        }

        if (name === "list_backup_jobs") {
            const state = (args as any)?.state || "FAILED";
            const hours = (args as any)?.hours || 24;
            const sinceDate = new Date(Date.now() - hours * 60 * 60 * 1000);

            const command = new ListBackupJobsCommand({
                ByState: state,
                ByCreatedAfter: sinceDate
            });
            const response = await backupClient.send(command);

            const jobs = response.BackupJobs?.map(j => ({
                BackupJobId: j.BackupJobId,
                State: j.State,
                CreationDate: j.CreationDate,
                BackupVaultName: j.BackupVaultName,
                ResourceArn: j.ResourceArn,
                StatusMessage: j.StatusMessage
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(jobs, null, 2) }]
            };
        }

        if (name === "list_open_security_groups") {
            const checkPorts = (args as any)?.ports; // If undefined, we check for ANY open port

            // If user specifically requests some ports, use them. If checksPorts is undefined/empty, means "any port".
            // But if user passes [], it might mean "any" or "none". Let's assume undefined means "any".
            const checkSpecificPorts = checkPorts && checkPorts.length > 0;

            const command = new DescribeSecurityGroupsCommand({
                Filters: [{ Name: "ip-permission.cidr", Values: ["0.0.0.0/0"] }]
            });
            const response = await ec2Client.send(command);

            const openSGs = response.SecurityGroups?.filter(sg => {
                return sg.IpPermissions?.some(perm => {
                    const isGlobal = perm.IpRanges?.some(r => r.CidrIp === "0.0.0.0/0");
                    if (!isGlobal) return false;

                    if (!checkSpecificPorts) return true; // If we aren't filtering by specific ports, then ANY 0.0.0.0/0 is a match.

                    // Check if it overlaps with checked ports or is all traffic
                    if (perm.IpProtocol === "-1") return true; // All traffic
                    const fromPort = perm.FromPort || 0;
                    const toPort = perm.ToPort || 65535;
                    return checkPorts.some((p: number) => p >= fromPort && p <= toPort);
                });
            }).map(sg => ({
                GroupId: sg.GroupId,
                GroupName: sg.GroupName,
                Description: sg.Description,
                OpenPorts: sg.IpPermissions?.filter(perm =>
                    perm.IpRanges?.some(r => r.CidrIp === "0.0.0.0/0") &&
                    (!checkSpecificPorts || perm.IpProtocol === "-1" || checkPorts.some((p: number) => p >= (perm.FromPort || 0) && p <= (perm.ToPort || 65535)))
                ).map(p => p.IpProtocol === "-1" ? "All" : `${p.FromPort}-${p.ToPort}`)
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(openSGs, null, 2) }]
            };
        }

        if (name === "list_unused_ebs_volumes") {
            const command = new DescribeVolumesCommand({
                Filters: [{ Name: "status", Values: ["available"] }]
            });
            const response = await ec2Client.send(command);

            const volumes = response.Volumes?.map(v => ({
                VolumeId: v.VolumeId,
                Size: v.Size,
                Type: v.VolumeType,
                CreateTime: v.CreateTime,
                AvailabilityZone: v.AvailabilityZone
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(volumes, null, 2) }]
            };
        }

        if (name === "list_unassociated_eips") {
            const command = new DescribeAddressesCommand({});
            const response = await ec2Client.send(command);
            // Filter where AssociationId is missing
            const unusedEips = response.Addresses?.filter(a => !a.AssociationId).map(a => ({
                PublicIp: a.PublicIp,
                AllocationId: a.AllocationId,
                Domain: a.Domain
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(unusedEips, null, 2) }]
            };
        }

        if (name === "list_guardduty_findings") {
            // first list detectors
            const detectorsCmd = new ListDetectorsCommand({});
            const dResponse = await guardDutyClient.send(detectorsCmd);
            const detectorId = dResponse.DetectorIds?.[0];

            if (!detectorId) {
                return { content: [{ type: "text", text: "No GuardDuty detector found." }] };
            }

            const severity = (args as any)?.severity || 4;
            const limit = (args as any)?.limit || 10;

            const listCmd = new ListFindingsCommand({
                DetectorId: detectorId,
                FindingCriteria: { Criterion: { severity: { Gte: severity } } },
                MaxResults: limit
            });
            const listResponse = await guardDutyClient.send(listCmd);

            if (!listResponse.FindingIds || listResponse.FindingIds.length === 0) {
                return { content: [{ type: "text", text: "No findings found." }] };
            }

            const getCmd = new GetFindingsCommand({
                DetectorId: detectorId,
                FindingIds: listResponse.FindingIds
            });
            const getResponse = await guardDutyClient.send(getCmd);

            const findings = getResponse.Findings?.map(f => ({
                Title: f.Title,
                Severity: f.Severity,
                Type: f.Type,
                Region: f.Region,
                ResourceId: f.Resource?.InstanceDetails?.InstanceId || "N/A"
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(findings, null, 2) }]
            };
        }

        if (name === "get_recent_logs") {
            const groupName = (args as any).log_group_name;
            const limit = (args as any)?.limit || 20;

            // Get latest stream
            const streamCmd = new DescribeLogStreamsCommand({
                logGroupName: groupName,
                orderBy: "LastEventTime",
                descending: true,
                limit: 1
            });

            try {
                const streamResp = await cloudWatchLogsClient.send(streamCmd);
                const streamName = streamResp.logStreams?.[0]?.logStreamName;

                if (!streamName) {
                    return { content: [{ type: "text", text: "No log streams found." }] };
                }

                const eventsCmd = new GetLogEventsCommand({
                    logGroupName: groupName,
                    logStreamName: streamName,
                    limit: limit,
                    startFromHead: false
                });
                const eventsResp = await cloudWatchLogsClient.send(eventsCmd);

                const logs = eventsResp.events?.map(e => ({
                    Timestamp: new Date(e.timestamp || 0).toISOString(),
                    Message: e.message
                })) || [];

                return {
                    content: [{ type: "text", text: JSON.stringify(logs, null, 2) }]
                };

            } catch (err: any) {
                return { content: [{ type: "text", text: `Error fetching logs: ${err.message}` }], isError: true };
            }
        }

        if (name === "search_cloudwatch_logs") {
            const groupName = (args as any).log_group_name;
            const filterPattern = (args as any).filter_pattern;
            const limit = (args as any)?.limit || 50;
            const hours = (args as any)?.hours || 24;

            const endTime = (args as any)?.end_time ? new Date((args as any).end_time).getTime() : Date.now();
            const startTime = (args as any)?.start_time ? new Date((args as any).start_time).getTime() : endTime - (hours * 60 * 60 * 1000);

            try {
                const command = new FilterLogEventsCommand({
                    logGroupName: groupName,
                    filterPattern: filterPattern,
                    startTime: startTime,
                    endTime: endTime,
                    limit: limit
                });

                const response = await cloudWatchLogsClient.send(command);

                const events = response.events?.map(e => ({
                    Timestamp: new Date(e.timestamp || 0).toISOString(),
                    Message: e.message,
                    LogStreamName: e.logStreamName
                })) || [];

                if (events.length === 0) {
                    return { content: [{ type: "text", text: "No matching logs found." }] };
                }

                return { content: [{ type: "text", text: JSON.stringify(events, null, 2) }] };
            } catch (err: any) {
                return { content: [{ type: "text", text: `Error searching logs: ${err.message}` }], isError: true };
            }
        }

        if (name === "list_cloudtrail_changes") {
            const resourceId = (args as any)?.resource_id;
            const lookupKey = (args as any)?.lookup_key || (resourceId ? "ResourceName" : undefined);
            const lookupValue = resourceId || (args as any)?.lookup_value;
            const days = (args as any)?.days || 7;

            if (!lookupKey || !lookupValue) {
                return { content: [{ type: "text", text: "Please provide a resource_id OR a lookup_key and lookup_value." }], isError: true };
            }

            const startTime = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

            const command = new LookupEventsCommand({
                LookupAttributes: [{ AttributeKey: lookupKey, AttributeValue: lookupValue }],
                StartTime: startTime,
                MaxResults: 50
            });

            const response = await cloudTrailClient.send(command);

            // Filter for mutations (not ReadOnly)
            // Note: 'ReadOnly' field in event isn't always populated in LookupEvents response types directly in all SDK versions, 
            // but we can infer or it is often there. Some events don't have it.
            // We'll primarily rely on showing the event name and letting user see.
            // But we can try to filter if resource JSON is parsed.

            const events = response.Events?.map(e => {
                let isReadOnly = true;
                // Try to guess read-only if not explicit. 
                // Usually "Get", "Describe", "List" are read. "Create", "Update", "Delete", "Put", "Modify" are write.
                const name = e.EventName || "";
                if (name.startsWith("Get") || name.startsWith("Describe") || name.startsWith("List")) {
                    isReadOnly = true;
                } else {
                    isReadOnly = false;
                }

                // If Resources tag is present, it's useful
                return {
                    EventTime: e.EventTime,
                    EventName: e.EventName,
                    Username: e.Username,
                    EventSource: e.EventSource,
                    ResourceName: e.Resources?.[0]?.ResourceName,
                    IsAssumedReadOnly: isReadOnly
                };
            }).filter(e => !e.IsAssumedReadOnly) || []; // Show only changes

            return { content: [{ type: "text", text: JSON.stringify(events, null, 2) }] };
        }

        if (name === "list_access_denied_events") {
            const limit = (args as any)?.limit || 20;
            // LookupEvents doesn't natively support filtering by 'AccessDenied' error code directly via LookupAttributes 
            // the way we want (it allows specific keys).
            // Best approach: Fetch recent events and client-side filter for ErrorCode.

            const command = new LookupEventsCommand({
                MaxResults: 50 // Fetch a bit more to filter
            });
            const response = await cloudTrailClient.send(command);

            // Note: LookupEvents output (Events) doesn't always contain ErrorCode as a top-level field?
            // Actually, LookupEvents output contains 'CloudTrailEvent' string which has the full JSON.

            const deniedEvents = response.Events?.map(e => {
                let errorCode = "N/A";
                let errorMessage = "N/A";

                if (e.CloudTrailEvent) {
                    try {
                        const json = JSON.parse(e.CloudTrailEvent);
                        errorCode = json.errorCode;
                        errorMessage = json.errorMessage;
                    } catch (err) { }
                }

                return {
                    EventTime: e.EventTime,
                    EventName: e.EventName,
                    Username: e.Username,
                    ErrorCode: errorCode,
                    ErrorMessage: errorMessage
                };
            }).filter(e => e.ErrorCode && (e.ErrorCode === "AccessDenied" || e.ErrorCode === "Client.UnauthorizedOperation" || e.ErrorCode.includes("Unauthorized")))
                .slice(0, limit) || [];

            return { content: [{ type: "text", text: JSON.stringify(deniedEvents, null, 2) }] };
        }

        if (name === "get_service_health") {
            const command = new DescribeEventsCommand({
                filter: { eventStatusCodes: ["open", "upcoming"] }
            });
            const response = await healthClient.send(command);

            const events = response.events?.map(e => ({
                EventTypeCode: e.eventTypeCode,
                Service: e.service,
                Region: e.region,
                StartTime: e.startTime,
                Status: e.statusCode,
                Description: e.eventScopeCode
            })) || [];

            return {
                content: [{ type: "text", text: JSON.stringify(events, null, 2) }]
            };
        }

        if (name === "list_load_balancers") {
            const command = new DescribeLoadBalancersCommand({});
            const response = await elbv2Client.send(command);
            const lbs = response.LoadBalancers?.map(lb => ({
                LoadBalancerName: lb.LoadBalancerName,
                DNSName: lb.DNSName,
                Type: lb.Type,
                Scheme: lb.Scheme,
                VpcId: lb.VpcId,
                State: lb.State?.Code,
                LoadBalancerArn: lb.LoadBalancerArn
            })) || [];
            return { content: [{ type: "text", text: JSON.stringify(lbs, null, 2) }] };
        }

        if (name === "list_target_groups") {
            const lbArn = (args as any)?.load_balancer_arn;
            const command = new DescribeTargetGroupsCommand(lbArn ? { LoadBalancerArn: lbArn } : {});
            const response = await elbv2Client.send(command);
            const tgs = response.TargetGroups?.map(tg => ({
                TargetGroupName: tg.TargetGroupName,
                Protocol: tg.Protocol,
                Port: tg.Port,
                TargetType: tg.TargetType,
                TargetGroupArn: tg.TargetGroupArn,
                LoadBalancerArns: tg.LoadBalancerArns
            })) || [];
            return { content: [{ type: "text", text: JSON.stringify(tgs, null, 2) }] };
        }

        if (name === "list_listener_rules") {
            const lbArn = (args as any).load_balancer_arn;

            const listenersCmd = new DescribeListenersCommand({ LoadBalancerArn: lbArn });
            const listenersResp = await elbv2Client.send(listenersCmd);
            const listeners = listenersResp.Listeners || [];

            const detailedListeners = [];

            for (const listener of listeners) {
                if (!listener.ListenerArn) continue;

                const rulesCmd = new DescribeRulesCommand({ ListenerArn: listener.ListenerArn });
                const rulesResp = await elbv2Client.send(rulesCmd);

                detailedListeners.push({
                    ListenerArn: listener.ListenerArn,
                    Port: listener.Port,
                    Protocol: listener.Protocol,
                    Rules: rulesResp.Rules?.map(r => ({
                        Priority: r.Priority,
                        Conditions: r.Conditions?.map(c => ({
                            Field: c.Field,
                            Values: c.Values,
                            HostHeaderConfig: c.HostHeaderConfig,
                            PathPatternConfig: c.PathPatternConfig
                        })),
                        Actions: r.Actions?.map(a => ({
                            Type: a.Type,
                            TargetGroupArn: a.TargetGroupArn
                        })),
                        IsDefault: r.IsDefault
                    }))
                });
            }

            return { content: [{ type: "text", text: JSON.stringify(detailedListeners, null, 2) }] };
        }



        if (name === "get_target_health") {
            const tgArn = (args as any)?.target_group_arn;
            const command = new DescribeTargetHealthCommand({ TargetGroupArn: tgArn });
            const response = await elbv2Client.send(command);
            const healths = response.TargetHealthDescriptions?.map(th => ({
                Target: { Id: th.Target?.Id, Port: th.Target?.Port },
                State: th.TargetHealth?.State,
                Reason: th.TargetHealth?.Reason,
                Description: th.TargetHealth?.Description
            })) || [];
            return { content: [{ type: "text", text: JSON.stringify(healths, null, 2) }] };
        }

        if (name === "list_web_acls") {
            const scope = (args as any)?.scope || "REGIONAL";
            const command = new ListWebACLsCommand({ Scope: scope });
            const response = await wafv2Client.send(command);
            const acls = response.WebACLs?.map(acl => ({
                Name: acl.Name,
                Id: acl.Id,
                ARN: acl.ARN,
                Description: acl.Description
            })) || [];
            return { content: [{ type: "text", text: JSON.stringify(acls, null, 2) }] };
        }

        if (name === "get_waf_sampled_requests") {
            const aclArn = (args as any)?.web_acl_arn;
            const metricName = (args as any)?.rule_metric_name;
            const scope = (args as any)?.scope || "REGIONAL";
            const timeWindow = (args as any)?.time_window_seconds || 3600;

            // WAFv2 Sampled Requests requires a time window
            const endTime = new Date();
            const startTime = new Date(endTime.getTime() - timeWindow * 1000);

            const command = new GetSampledRequestsCommand({
                WebAclArn: aclArn,
                RuleMetricName: metricName,
                Scope: scope,
                TimeWindow: { StartTime: startTime, EndTime: endTime },
                MaxItems: 100
            });
            const response = await wafv2Client.send(command);

            const requests = response.SampledRequests?.map(r => ({
                ClientIP: r.Request?.ClientIP,
                Country: r.Request?.Country,
                URI: r.Request?.URI,
                Method: r.Request?.Method,
                Headers: r.Request?.Headers,
                Action: r.Action,
                Timestamp: r.Timestamp
            })) || [];
            return { content: [{ type: "text", text: JSON.stringify(requests, null, 2) }] };
        }

        if (name === "check_ip_in_waf") {
            const ip = (args as any)?.ip_address;
            const scopes: ("REGIONAL" | "CLOUDFRONT")[] = ["REGIONAL", "CLOUDFRONT"];
            const foundIn: any[] = [];

            for (const scope of scopes) {
                try {
                    const listCmd = new ListIPSetsCommand({ Scope: scope, Limit: 100 });
                    const listResp = await wafv2Client.send(listCmd);

                    const ipSets = listResp.IPSets || [];

                    for (const setSummary of ipSets) {
                        if (!setSummary.Name || !setSummary.Id) continue;

                        const getCmd = new GetIPSetCommand({
                            Name: setSummary.Name,
                            Id: setSummary.Id,
                            Scope: scope
                        });
                        const getResp = await wafv2Client.send(getCmd);
                        const addresses = getResp.IPSet?.Addresses || [];

                        if (checkIp(ip, addresses)) {
                            foundIn.push({
                                IPSetName: setSummary.Name,
                                IPSetId: setSummary.Id,
                                IPSetARN: setSummary.ARN,
                                Scope: scope,
                                Description: getResp.IPSet?.Description
                            });
                        }
                    }
                } catch (err) {
                    console.error(`Error checking WAF scope ${scope}:`, err);
                }
            }

            if (foundIn.length === 0) {
                return { content: [{ type: "text", text: `IP ${ip} not found in any WAF IP Sets.` }] };
            }

            return { content: [{ type: "text", text: JSON.stringify(foundIn, null, 2) }] };
        }

        if (name === "get_metric_statistics") {
            const { namespace, metric_name, dimensions, start_time, end_time, period, statistics } = (args as any);

            // Defualts
            const actualStartTime = start_time ? new Date(start_time) : new Date(Date.now() - 24 * 60 * 60 * 1000); // 24h ago
            const actualEndTime = end_time ? new Date(end_time) : new Date();
            const actualPeriod = period || 300; // 5 mins
            const actualStats = statistics || ["Average"];

            // Convert dimensions to right format: { Name, Value } is already expected from args.

            const command = new GetMetricStatisticsCommand({
                Namespace: namespace,
                MetricName: metric_name,
                Dimensions: dimensions,
                StartTime: actualStartTime,
                EndTime: actualEndTime,
                Period: actualPeriod,
                Statistics: actualStats
            });
            const response = await cloudWatchClient.send(command);

            const datapoints = response.Datapoints?.sort((a, b) => (a.Timestamp?.getTime() || 0) - (b.Timestamp?.getTime() || 0))
                .map(dp => ({
                    Timestamp: dp.Timestamp,
                    Average: dp.Average,
                    Maximum: dp.Maximum,
                    Minimum: dp.Minimum,
                    Sum: dp.Sum,
                    SampleCount: dp.SampleCount,
                    Unit: dp.Unit
                })) || [];

            return { content: [{ type: "text", text: JSON.stringify(datapoints, null, 2) }] };
        }

        if (name === "list_sns_topics") {
            const command = new ListTopicsCommand({});
            const response = await snsClient.send(command);
            const topics = response.Topics?.map(t => ({ TopicArn: t.TopicArn })) || [];
            return { content: [{ type: "text", text: JSON.stringify(topics, null, 2) }] };
        }

        if (name === "list_record_sets") {
            const zoneId = (args as any)?.hosted_zone_id;
            const command = new ListResourceRecordSetsCommand({ HostedZoneId: zoneId });
            const response = await route53Client.send(command);

            const records = response.ResourceRecordSets?.map(r => ({
                Name: r.Name,
                Type: r.Type,
                TTL: r.TTL,
                ResourceRecords: r.ResourceRecords,
                AliasTarget: r.AliasTarget
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(records, null, 2) }] };
        }

        if (name === "list_hosted_zones") {
            const command = new ListHostedZonesCommand({});
            const response = await route53Client.send(command);

            const zones = response.HostedZones?.map(z => ({
                Id: z.Id,
                Name: z.Name,
                Config: z.Config,
                ResourceRecordSetCount: z.ResourceRecordSetCount
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(zones, null, 2) }] };
        }

        if (name === "list_ecs_clusters") {
            const command = new ListClustersCommand({});
            const response = await ecsClient.send(command);
            // Detail describe to get task counts
            const clusters = response.clusterArns || [];
            if (clusters.length === 0) return { content: [{ type: "text", text: "[]" }] };

            const descParams = { clusters: clusters };
            const descCommand = new DescribeClustersCommand(descParams);
            const descResponse = await ecsClient.send(descCommand);

            const clusterDetails = descResponse.clusters?.map(c => ({
                clusterName: c.clusterName,
                status: c.status,
                runningTasksCount: c.runningTasksCount,
                pendingTasksCount: c.pendingTasksCount,
                activeServicesCount: c.activeServicesCount
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(clusterDetails, null, 2) }] };
        }

        if (name === "list_ecs_services") {
            const cluster = (args as any).cluster;
            const command = new ListServicesCommand({ cluster });
            const response = await ecsClient.send(command);

            const services = response.serviceArns || [];
            if (services.length === 0) return { content: [{ type: "text", text: "[]" }] };

            // Describe for more info
            const batch = services.slice(0, 10);
            const descCommand = new DescribeServicesCommand({ cluster, services: batch });
            const descResponse = await ecsClient.send(descCommand);

            const serviceDetails = descResponse.services?.map(s => ({
                serviceName: s.serviceName,
                status: s.status,
                desiredCount: s.desiredCount,
                runningCount: s.runningCount,
                pendingCount: s.pendingCount,
                taskDefinition: s.taskDefinition
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(serviceDetails, null, 2) }] };
        }

        if (name === "list_eks_clusters") {
            const command = new ListEksClustersCommand({});
            const response = await eksClient.send(command);
            return { content: [{ type: "text", text: JSON.stringify(response.clusters || [], null, 2) }] };
        }

        if (name === "list_auto_scaling_groups") {
            const command = new DescribeAutoScalingGroupsCommand({});
            const response = await asgClient.send(command);

            const asgs = response.AutoScalingGroups?.map(g => ({
                AutoScalingGroupName: g.AutoScalingGroupName,
                MinSize: g.MinSize,
                MaxSize: g.MaxSize,
                DesiredCapacity: g.DesiredCapacity,
                Instances: g.Instances?.length
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(asgs, null, 2) }] };
        }

        if (name === "list_scaling_activities") {
            const groupName = (args as any).auto_scaling_group_name;
            const command = new DescribeScalingActivitiesCommand({ AutoScalingGroupName: groupName, MaxRecords: 10 });
            const response = await asgClient.send(command);

            const activities = response.Activities?.map(a => ({
                ActivityId: a.ActivityId,
                Description: a.Description,
                Cause: a.Cause,
                StartTime: a.StartTime,
                StatusCode: a.StatusCode
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(activities, null, 2) }] };
        }

        if (name === "list_cloudfront_distributions") {
            const command = new ListDistributionsCommand({});
            const response = await cloudFrontClient.send(command);

            const dists = response.DistributionList?.Items?.map(d => ({
                Id: d.Id,
                DomainName: d.DomainName,
                Status: d.Status,
                Enabled: d.Enabled,
                Aliases: d.Aliases?.Items
            })) || [];

            return { content: [{ type: "text", text: JSON.stringify(dists, null, 2) }] };
        }

        if (name === "list_secrets") {
            const command = new ListSecretsCommand({});
            const response = await secretsManagerClient.send(command);
            const secrets = response.SecretList?.map(s => ({ Name: s.Name, Description: s.Description })) || [];
            return { content: [{ type: "text", text: JSON.stringify(secrets, null, 2) }] };
        }

        if (name === "list_ssm_parameters") {
            // DescribeParameters mainly lists them
            const command = new DescribeParametersCommand({});
            const response = await ssmClient.send(command);
            const params = response.Parameters?.map(p => ({ Name: p.Name, Type: p.Type, Description: p.Description })) || [];
            return { content: [{ type: "text", text: JSON.stringify(params, null, 2) }] };
        }

        if (name === "list_cloudformation_stacks") {
            const command = new ListStacksCommand({ StackStatusFilter: ["CREATE_COMPLETE", "UPDATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS"] });
            const response = await cfnClient.send(command);
            const stacks = response.StackSummaries?.map(s => ({
                StackName: s.StackName,
                StackStatus: s.StackStatus,
                DriftInformation: s.DriftInformation,
                CreationTime: s.CreationTime
            })) || [];
            return { content: [{ type: "text", text: JSON.stringify(stacks, null, 2) }] };
        }

        if (name === "list_dynamodb_tables") {
            const command = new ListTablesCommand({});
            const response = await dynamoDbClient.send(command);
            return { content: [{ type: "text", text: JSON.stringify(response.TableNames || [], null, 2) }] };
        }

        if (name === "list_trusted_advisor_checks") {
            try {
                const command = new DescribeTrustedAdvisorChecksCommand({ language: "en" });
                const response = await supportClient.send(command);
                const checks = response.checks?.map(c => ({
                    id: c.id,
                    name: c.name,
                    category: c.category
                })) || [];
                return { content: [{ type: "text", text: JSON.stringify(checks, null, 2) }] };
            } catch (error) {
                // Return clear error if Support API is not available (e.g. Basic Support plan)
                return { content: [{ type: "text", text: JSON.stringify({ error: "Trusted Advisor check failed. Ensure you have Business/Enterprise support or access.", details: (error as Error).message }) }] };
            }
        }

        throw new Error(`Unknown tool: ${name}`);
    } catch (error: any) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error executing ${name}: ${error.message}`,
                },
            ],
            isError: true,
        };
    }
});

// Start the server
const transport = new StdioServerTransport();
await server.connect(transport);
