package breakability

import (
	breakabilityapi "github.com/snyk/studio-mcp/internal/apiclients/breakability/2024-10-15"
)

type PackageUpgrade struct {
	Name        string `json:"name"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
}

type BreakabilityResponse struct {
	RiskLevel    string `json:"risk_level"`
	Assessment   string `json:"assessment"`
	Instructions string `json:"instructions"`
	PublicId     string `json:"-"`
}

func BuildBreakabilityResponse(attrs *breakabilityapi.BreakabilityResponseAttributes) *BreakabilityResponse {
	response := &BreakabilityResponse{
		RiskLevel:  string(attrs.RiskLevel),
		Assessment: attrs.Summary,
	}

	if response.RiskLevel == "high" {
		response.Instructions = "Breaking change detected. Try to find "
	}

	return response
}

func ToAPIUpgrades(upgrades []PackageUpgrade) []breakabilityapi.Upgrade {
	apiUpgrades := make([]breakabilityapi.Upgrade, len(upgrades))
	for i, u := range upgrades {
		apiUpgrades[i] = breakabilityapi.Upgrade{
			Name:        u.Name,
			FromVersion: u.FromVersion,
			ToVersion:   u.ToVersion,
		}
	}
	return apiUpgrades
}
