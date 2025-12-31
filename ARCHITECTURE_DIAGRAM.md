
# 🏗️ AWS MCP Server - Architecture & Flow

This diagram illustrates how your natural language request travels from the AI assistant to your AWS infrastructure and back.

```mermaid
graph TD
    %% Define Styles
    classDef user fill:#f9f,stroke:#333,stroke-width:2px,color:black,font-weight:bold;
    classDef ai fill:#bbf,stroke:#333,stroke-width:2px,color:black;
    classDef mcp fill:#ff9,stroke:#333,stroke-width:4px,color:black,font-weight:bold;
    classDef cloud fill:#9f9,stroke:#333,stroke-width:2px,color:black;

    %% Nodes
    User(("👤 User")):::user
    AI("🤖 AI Assistant\n(Claude / Gemini / IDE)"):::ai
    MCP_Protocol{{"🔌 MCP Protocol"}}:::mcp
    Server("⚙️ AWS MCP Server\n(Running Locally/Docker)"):::mcp
    AWS_SDK("📦 AWS SDK v3")
    AWS_Cloud("☁️ AWS Cloud\n(Resources & APIs)"):::cloud

    %% Flow - Request
    User -->|1. 'Check my AWS costs'| AI
    AI -->|2. Identifies Tool\n'get_recent_cost'| MCP_Protocol
    MCP_Protocol -->|3. Sends Tool Call| Server
    Server -->|4. Executes Command| AWS_SDK
    AWS_SDK -->|5. API Request| AWS_Cloud

    %% Flow - Response
    AWS_Cloud -.->|6. Returns Data (JSON)| AWS_SDK
    AWS_SDK -.->|7. Returns Object| Server
    Server -.->|8. Formats Result| MCP_Protocol
    MCP_Protocol -.->|9. Sends Tool Result| AI
    AI -.->|10. Summarizes Answer| User

    %% Grouping
    subgraph "Your Machine / Local Environment"
        AI
        MCP_Protocol
        Server
        AWS_SDK
    end

    subgraph "External"
        AWS_Cloud
    end
```

### 📝 Step-by-Step Explanation

1. **User Request**: You ask a natural language question (e.g., *"What is my cloud spend?*").
2. **Tool Selection**: The AI analyzes your intent and decides it needs the `get_recent_cost` tool.
3. **MCP Protocol**: The AI sends a request via the Model Context Protocol to your local server.
4. **Execution**: The **AWS MCP Server** receives the request and translates it into a specific AWS SDK function call.
5. **API Call**: The command is sent securely to the AWS Cloud using your local credentials.
6. **Data Retrieval**: AWS returns the raw data (JSON).
7. **Response Loop**: The data flows back to the AI, which interprets the JSON and generates a human-readable summary for you.
