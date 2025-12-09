package shared

const (
	ToolNameParam       = "tool"
	RuleTypeParam       = "rule-type"
	RuleTypeSmart       = "smart-apply"
	RuleTypeAlwaysApply = "always-apply"

	RulesScopeParam      = "rules-scope"
	WorkspacePath        = "workspace"
	ServerNameKey        = "Snyk"
	McpConfigureCallback = "mcp-configure-callback"
	RemoveParam          = "rm"
	ConfigureMcpParam    = "configure-mcp"   // Flag to enable/disable MCP server configuration
	ConfigureRulesParam  = "configure-rules" // Flag to enable/disable rules configuration

	RulesGlobalScope    = "global"
	RulesWorkspaceScope = "workspace"
)

const (
	TrustedFoldersParam        = "trusted-folders"
	IdeConfigPathParam         = "ide-config-path"
	OutputDirParam      string = "output-dir"
)

type McpConfigCallBack func(cmd string, args []string, env map[string]string) error

type McpEnvMap map[string]string
