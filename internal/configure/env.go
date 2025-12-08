package configure

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/studio-mcp/shared"
)

// getSnykMcpEnv extracts Snyk-specific environment variables from configuration
func getSnykMcpEnv(config configuration.Configuration) shared.EnvMap {
	env := make(shared.EnvMap)

	if org := config.GetString(configuration.ORGANIZATION); org != "" {
		env["SNYK_CFG_ORG"] = org
	}
	if apiEndpoint := config.GetString(configuration.API_URL); apiEndpoint != "" {
		env["SNYK_API"] = apiEndpoint
	}
	if trustedFolders := config.GetString(shared.TrustedFoldersParam); trustedFolders != "" {
		env["TRUSTED_FOLDERS"] = trustedFolders
	}
	if ideConfigPath := config.GetString(shared.IdeConfigPathParam); ideConfigPath != "" {
		env["IDE_CONFIG_PATH"] = ideConfigPath
	}

	return env
}
