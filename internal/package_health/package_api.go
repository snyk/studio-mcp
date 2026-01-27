package package_health

import (
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

func BuildPackageInfoResponse(attrs *packageapi.PackageVersionAttributes) *PackageInfoResponse {
	response := &PackageInfoResponse{
		PackageName:    attrs.PackageName,
		PackageVersion: attrs.PackageVersion,
		Ecosystem:      attrs.Ecosystem,
		Language:       attrs.Language,
		Health:         attrs.PackageHealth,
	}

	if attrs.Description != nil {
		response.Recommendation = *attrs.Description
	}
	if attrs.PackageHealth != nil && attrs.PackageHealth.Description != nil {
		response.Recommendation = *attrs.PackageHealth.Description
	}

	return response
}

func BuildPackageInfoResponseFromPackage(attrs *packageapi.PackageAttributes) *PackageInfoResponse {
	response := &PackageInfoResponse{
		PackageName: attrs.PackageName,
		Ecosystem:   attrs.Ecosystem,
		Language:    attrs.Language,
		Health:      attrs.PackageHealth,
	}

	if attrs.Description != nil {
		response.Description = *attrs.Description
	}
	if attrs.LatestVersion != nil {
		response.LatestVersion = *attrs.LatestVersion
	}
	if attrs.PackageHealth != nil && attrs.PackageHealth.Description != nil {
		response.Recommendation = *attrs.PackageHealth.Description
	}

	return response
}
