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

	RulesGlobalScope    = "global"
	RulesWorkspaceScope = "workspace"
)

const (
	TrustedFoldersParam        = "trusted-folders"
	IdeConfigPathParam         = "ide-config-path"
	OutputDirParam      string = "output-dir"
)

type ConfigCallBack func(cmd string, args []string, env map[string]string) error

type EnvMap map[string]string
