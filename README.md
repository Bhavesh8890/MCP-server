# AWS MCP Server for Shellkode

This is a Model Context Protocol (MCP) server that provides read-only access to AWS resources.
It is built using TypeScript and the AWS SDK v3.

## Features

This server exposes the following tools:

- `get_aws_caller_identity`: Verify the current AWS credentials.
- `list_s3_buckets`: List all S3 buckets.
- `list_ec2_instances`: List EC2 instances in the configured region (or a specified region).
- `list_iam_users`: List IAM users.

## Prerequisites

- Node.js (v16 or higher)
- AWS Credentials (Access Key ID and Secret Access Key) with read-only permissions.

## Setup

1. **Install dependencies**:

    ```bash
    npm install
    ```

2. **Build the project**:

    ```bash
    npm run build
    ```

    (Note: `npm run build` is not defined in package.json yet, command is `npx tsc`)

## Usage (Private / Team)

Since this is a private tool, you can share it with your team in two main ways:

### Option 1: Share via Git (Recommended)

1. **Push** this code to your private repository (GitHub, GitLab, etc.).
2. **Team members** should clone the repository:

    ```bash
    git clone <your-private-repo-url>
    cd mcp-server-shellkode
    npm install
    npm run build
    ```

3. **Configure MCP Client**:
    Use the absolute path to the locally built file.

    ```json
    {
      "mcpServers": {
        "aws-shellkode": {
          "command": "node",
          "args": ["/path/to/cloned/repo/dist/index.js"],
          "env": {
            "AWS_ACCESS_KEY_ID": "YOUR_ACCESS_KEY",
            "AWS_SECRET_ACCESS_KEY": "YOUR_SECRET_KEY",
            "AWS_REGION": "us-east-1"
          }
        }
      }
    }
    ```

### Option 2: Share as a Single File (.tgz)

You can package the server into a single file and send it to your team (Slack, Email, Sharepoint).

1. **Create the package**:

    ```bash
    npm pack
    ```

    This creates a file like `mcp-server-shellkode-1.0.0.tgz`.

2. **Team members** install it globally (or locally):

    ```bash
    npm install -g mcp-server-shellkode-1.0.0.tgz
    ```

3. **Configure MCP Client**:
    If installed globally, they can run it directly:

    ```json
    {
      "mcpServers": {
        "aws-shellkode": {
          "command": "mcp-server-shellkode",
          "args": [],
          "env": { ... }
        }
      }
    }
    ```

### Option 2: Running Locally

If you cloned the repository and built it locally:

**Command**: `node`
**Args**: `/path/to/dist/index.js` (Absolute path recommended)

**Example Configuration (JSON)**:

```json
{
  "mcpServers": {
    "aws-shellkode": {
      "command": "node",
      "args": ["/Users/bhaveshkumarparmar/Desktop/Shellkode/MSP-Projects/MCP-server-Shellkode/dist/index.js"],
      "env": {
        "AWS_ACCESS_KEY_ID": "YOUR_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY": "YOUR_SECRET_KEY",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Development

To run the server in development mode (watching for changes):

```bash
npx tsx watch src/index.ts
```
