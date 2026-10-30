package shared

const (
	ToolNameParam = "tool"
	RuleTypeParam = "rule-type" // Accepted and ignored by mcp.configure.

	// Deprecated: mcp.configure no longer writes rules. Kept until snyk-ls stops setting it.
	RuleTypeSmart = "smart-apply"
	// Deprecated: mcp.configure no longer writes rules. Kept until snyk-ls stops setting it.
	RuleTypeAlwaysApply = "always-apply"

	RulesScopeParam    = "rules-scope"
	WorkspacePathParam = "workspace"
	ServerNameKey      = "Snyk"
	// Deprecated: mcp.configure no longer registers an MCP server. Kept until snyk-ls stops setting it.
	McpRegisterCallbackParam = "mcp-register-callback"
	RemoveParam              = "rm"
	ConfigureMcpParam        = "configure-mcp"   // Flag to enable/disable MCP server configuration
	ConfigureRulesParam      = "configure-rules" // Flag to enable/disable rules configuration

	RulesGlobalScope    = "global"
	RulesWorkspaceScope = "workspace"

	// MCP server configuration
	McpServerCommandPattern = "/snyk-"
	McpServerStdioArg1      = "mcp"
	McpServerStdioArg2      = "-t"
	McpServerStdioArg3      = "stdio"
)

const (
	// Deprecated: mcp.configure no longer writes an MCP server env. Kept until snyk-ls stops setting it.
	TrustedFoldersParam = "trusted-folders"
	// Deprecated: mcp.configure no longer writes an MCP server env. Kept until snyk-ls stops setting it.
	IdeConfigPathParam = "ide-config-path"

	OutputDirParam string = "output-dir"
)

// Deprecated: mcp.configure no longer registers an MCP server. Kept until snyk-ls stops setting it.
type McpRegisterCallback func(cmd string, args []string, env map[string]string) error
