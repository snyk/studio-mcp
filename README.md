# Snyk Studio MCP

MCP (Model Context Protocol) is an open protocol that standardizes how applications share context with large language models.

MCP can provide AI systems with additional information needed to generate accurate and relevant responses for use cases where the AI systems do not have the context, by integrating the AI systems with tools and platforms that have specific capabilities.&#x20;

You can integrate Snyk MCP into MCP-supporting tools to provide Snyk security context.

Snyk is introducing an MCP server as part of the Snyk CLI. This allows MCP-enabled agentic tools to integrate Snyk security scanning capabilities directly, thus bridging the gap between security scanning and AI-assisted workflows.

In environments or applications that use MCP, you can use the `snyk mcp` CLI command to:

* Invoke Snyk scans:\
  Trigger CLI security scans for code, dependencies, or configurations in your codebase in your current MCP context.
* Retrieve results:\
  Obtain Snyk security findings directly in your MCP-enabled tool or environment.

&#x20;The Snyk MCP server supports integrating the following Snyk security tools into an AI system:

* `snyk_sca_scan` (Open Source scan)
* `snyk_code_scan` (Code scan)
* `snyk_iac_scan` (IaC scan)
* `snyk_container_scan` (IaC scan)
* `snyk_sbom_scan` (SBOM file scan)
* `snyk_aibom` (Create AIBOM)
* `snyk_trust` (Trust a given folder before running a scan)
* `snyk_auth` (authentication)
* `snyk_logout` (logout)
* `snyk_auth_status` (authentication status check)
* `snyk_version` (version information)


Running `snyk_sca_scan` may execute third-party ecosystem tools (for example, Gradle or Maven) on your machine to fetch the project's dependency tree.


For more details, see the [Snyk MCP installation, configuration and startup](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/quickstart-guides-for-snyk-studio) and [Troubleshooting for the Snyk MCP server](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/troubleshooting) pages.

**This repository is closed to public contributions.**