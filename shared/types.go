package shared

const (
	ToolNameParam       = "tool"
	RuleTypeParam       = "rule-type"
	RuleTypeSmart       = "smart-apply"
	RuleTypeAlwaysApply = "always-apply"

	RulesScopeParam          = "rules-scope"
	WorkspacePathParam       = "workspace"
	ServerNameKey            = "Snyk"
	McpRegisterCallbackParam = "mcp-register-callback" // Callback function to register MCP server. Used from Language Server to register MCP server using native IDE API.
	RemoveParam              = "rm"
	ConfigureMcpParam        = "configure-mcp"   // Flag to enable/disable MCP server configuration
	ConfigureRulesParam      = "configure-rules" // Flag to enable/disable rules configuration

	RulesGlobalScope    = "global"
	RulesWorkspaceScope = "workspace"
)

const (
	TrustedFoldersParam        = "trusted-folders"
	IdeConfigPathParam         = "ide-config-path"
	OutputDirParam      string = "output-dir"
)

type McpRegisterCallback func(cmd string, args []string, env map[string]string) error

type McpEnvMap map[string]string
