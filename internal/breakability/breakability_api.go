package breakability

import (
	breakabilityapi "github.com/snyk/studio-mcp/internal/apiclients/breakability/2024-10-15"
)

const (
	HighRiskInstruction   = "IMPORTANT: Breaking change detected. If Snyk reported another upgrade path that is non-breaking use it. Otherwise, inform the user of the breaking change first."
	MediumRiskInstruction = "Check the assessment and determine if the change is breaking or not. If it is breaking, inform the user of the breaking change first. Otherwise, proceed with the upgrade."
	LowRiskInstruction    = "Non-breaking change, proceed with the upgrade."
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

	if response.RiskLevel == string(breakabilityapi.High) {
		response.Instructions = HighRiskInstruction
	} else if response.RiskLevel == string(breakabilityapi.Medium) {
		response.Instructions = MediumRiskInstruction
	} else if response.RiskLevel == string(breakabilityapi.Low) {
		response.Instructions = LowRiskInstruction
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
