package package_api

import (
	"fmt"
	"strings"

	packageapi "github.com/snyk/studio-mcp/internal/apiclients/package/2024-10-15"
)

// ValidEcosystems defines the allowed ecosystem values for the package info tool
var ValidEcosystems = map[string]bool{
	"npm":    true,
	"golang": true,
	"pypi":   true,
	"maven":  true,
	"nuget":  true,
}

// PackageInfoResponse represents the response structure for package info
type PackageInfoResponse struct {
	PackageName    string                    `json:"package_name"`
	PackageVersion string                    `json:"package_version,omitempty"`
	Ecosystem      string                    `json:"ecosystem"`
	Language       string                    `json:"language"`
	Description    string                    `json:"description,omitempty"`
	LatestVersion  string                    `json:"latest_version,omitempty"`
	Health         *packageapi.PackageHealth `json:"health,omitempty"`
	Recommendation string                    `json:"recommendation"`
}

func buildPackageRecommendationMessage(health *packageapi.PackageHealth) string {
	if health == nil || health.OverallRating == nil {
		return "Package health information not available. Proceed with caution."
	}

	if strings.ToLower(*health.OverallRating) == "healthy" {
		return fmt.Sprintf("Package appears healthy and safe to use.")
	} else if strings.ToLower(*health.OverallRating) == "review recommended" {
		return fmt.Sprintf("WARNING: Check the package and ask for approval before using it.")
	} else if strings.ToLower(*health.OverallRating) == "not recommended" {
		return fmt.Sprintf("WARNING: Do not use this package. Multiple issues were found")
	} else {
		return "Package health information not available. Proceed with caution."
	}
}

func BuildPackageInfoResponse(attrs *packageapi.PackageVersionAttributes) *PackageInfoResponse {
	recommendation := buildPackageRecommendationMessage(attrs.PackageHealth)

	response := &PackageInfoResponse{
		PackageName:    attrs.PackageName,
		PackageVersion: attrs.PackageVersion,
		Ecosystem:      attrs.Ecosystem,
		Language:       attrs.Language,
		Health:         attrs.PackageHealth,
		Recommendation: recommendation,
	}

	if attrs.Description != nil {
		response.Description = *attrs.Description
	}

	return response
}

func BuildPackageInfoResponseFromPackage(attrs *packageapi.PackageAttributes) *PackageInfoResponse {
	recommendation := buildPackageRecommendationMessage(attrs.PackageHealth)

	response := &PackageInfoResponse{
		PackageName:    attrs.PackageName,
		Ecosystem:      attrs.Ecosystem,
		Language:       attrs.Language,
		Health:         attrs.PackageHealth,
		Recommendation: recommendation,
	}

	if attrs.Description != nil {
		response.Description = *attrs.Description
	}
	if attrs.LatestVersion != nil {
		response.LatestVersion = *attrs.LatestVersion
	}

	return response
}
