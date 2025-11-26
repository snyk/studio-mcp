package configure

import (
	"os"
	"strings"
)

// stringSlicesEqual compares two string slices for equality
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// envMapsEqual compares two environment maps for equality
func envMapsEqual(a, b envMap) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// isExecutedViaNPMContext checks if the current program was executed
// within a context provided by npm (like 'npm run' or 'npx').
func isExecutedViaNPMContext() bool {
	// 'npm_execpath' is reliably set by modern npm/npx execution environments.
	npmExecPath := os.Getenv("npm_execpath")
	if npmExecPath != "" {
		return true
	}

	// --- Secondary Check: Executable Path (Detects temporary installs) ---
	// The executable path is os.Args[0]. We check for the '_npx' marker,
	// which indicates a temporary install from the npm cache.
	if len(os.Args) > 0 {
		executablePath := os.Args[0]
		// We look for "_npx" which is a common directory name in the npm cache structure
		// used for running temporary binaries.
		if strings.Contains(executablePath, "_npx") {
			return true
		}
	}

	return false
}
