// Package vulnscanner implements dependency vulnerability scanning via OSV.dev.
package vulnscanner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Dependency represents a single parsed dependency from a manifest file.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // "npm", "pypi", or "go"
}

// ParseManifest parses a package manifest and returns the list of dependencies.
// Supported ecosystems: "npm" (package.json, package-lock.json), "pip" (requirements.txt),
// and "go" (go.mod).
func ParseManifest(content string, ecosystem string) ([]Dependency, error) {
	switch ecosystem {
	case "npm":
		return parseNPM(content)
	case "pip":
		return parsePip(content)
	case "go":
		return parseGoMod(content)
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %q", ecosystem)
	}
}

// parseGoMod scans a go.mod file for require directives and returns the
// listed module dependencies with their versions.
func parseGoMod(content string) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	inBlock := false

	for _, raw := range lines {
		line := strings.TrimSpace(raw)

		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "require (") {
			inBlock = true
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			// Block require: "module/path v1.2.3"
			parts := strings.Fields(line)
			if len(parts) >= 2 && !strings.Contains(parts[0], "//") {
				name := parts[0]
				ver := parts[1]
				// Strip trailing comment (// indirect)
				if idx := strings.Index(ver, "//"); idx != -1 {
					ver = strings.TrimSpace(ver[:idx])
				}
				deps = append(deps, Dependency{Name: name, Version: ver, Ecosystem: "go"})
			}
			continue
		}

		// Single-line require: require module/path v1.2.3
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				name := parts[0]
				ver := parts[1]
				if idx := strings.Index(ver, "//"); idx != -1 {
					ver = strings.TrimSpace(ver[:idx])
				}
				deps = append(deps, Dependency{Name: name, Version: ver, Ecosystem: "go"})
			}
		}
	}

	return deps, nil
}

// parseNPM handles package.json and package-lock.json formats.
func parseNPM(content string) ([]Dependency, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var deps []Dependency

	// Try standard package.json format: "dependencies" and "devDependencies" maps
	for _, key := range []string{"dependencies", "devDependencies"} {
		rawSection, ok := raw[key]
		if !ok {
			continue
		}
		var section map[string]string
		if err := json.Unmarshal(rawSection, &section); err != nil {
			// If it's not a simple string map, skip (could be lock file format)
			continue
		}
		for name, versionConstraint := range section {
			deps = append(deps, Dependency{
				Name:      name,
				Version:   stripVersionPrefix(versionConstraint),
				Ecosystem: "npm",
			})
		}
	}

	// Try package-lock.json format: "packages" section
	if rawPackages, ok := raw["packages"]; ok {
		lockDeps := parseLockPackages(rawPackages)
		deps = append(deps, lockDeps...)
	}

	// Try package-lock.json legacy format: top-level "dependencies" with version objects
	// Only if we haven't already parsed simple string maps from "dependencies"
	if len(deps) == 0 {
		if rawDeps, ok := raw["dependencies"]; ok {
			lockDeps := parseLockDependencies(rawDeps)
			deps = append(deps, lockDeps...)
		}
	}

	return deps, nil
}

// parseLockPackages parses the "packages" field from package-lock.json v3 format.
// Each entry is keyed by relative path (e.g., "node_modules/express") with a "version" field.
func parseLockPackages(raw json.RawMessage) []Dependency {
	var packages map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &packages); err != nil {
		return nil
	}

	var deps []Dependency
	for path, pkg := range packages {
		if pkg.Version == "" {
			continue
		}
		// Extract package name from the path (e.g., "node_modules/express" -> "express")
		name := extractPackageName(path)
		if name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
		})
	}
	return deps
}

// parseLockDependencies parses the legacy "dependencies" field from package-lock.json v1/v2 format.
// Each entry is keyed by package name with a "version" field.
func parseLockDependencies(raw json.RawMessage) []Dependency {
	var lockDeps map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &lockDeps); err != nil {
		return nil
	}

	var deps []Dependency
	for name, pkg := range lockDeps {
		if pkg.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
		})
	}
	return deps
}

// extractPackageName extracts the package name from a lock file path.
// Examples:
//
//	"node_modules/express" -> "express"
//	"node_modules/@scope/pkg" -> "@scope/pkg"
//	"" -> "" (root entry, skip)
func extractPackageName(path string) string {
	if path == "" {
		return ""
	}
	const prefix = "node_modules/"
	idx := strings.LastIndex(path, prefix)
	if idx == -1 {
		return ""
	}
	name := path[idx+len(prefix):]
	if name == "" {
		return ""
	}
	return name
}

// stripVersionPrefix removes common semver constraint prefixes from a version string.
func stripVersionPrefix(version string) string {
	version = strings.TrimSpace(version)
	// Strip multi-character prefixes first
	for _, prefix := range []string{">=", "<=", "~>"} {
		if strings.HasPrefix(version, prefix) {
			return strings.TrimSpace(version[len(prefix):])
		}
	}
	// Strip single-character prefixes
	for _, prefix := range []string{"^", "~", ">", "<", "="} {
		if strings.HasPrefix(version, prefix) {
			return strings.TrimSpace(version[len(prefix):])
		}
	}
	return version
}

// parsePip handles requirements.txt format.
func parsePip(content string) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Skip flags (lines starting with -)
		if strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		name, version := parsePipLine(line)
		if name == "" {
			continue
		}

		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "pypi",
		})
	}

	return deps, nil
}

// parsePipLine splits a requirements.txt line into name and version.
// Supported operators: ==, >=, <=, !=, ~=
func parsePipLine(line string) (name, version string) {
	// Try splitting on two-char operators first
	for _, op := range []string{"==", ">=", "<=", "!=", "~="} {
		if idx := strings.Index(line, op); idx != -1 {
			name = strings.TrimSpace(line[:idx])
			version = strings.TrimSpace(line[idx+len(op):])
			return name, version
		}
	}

	// No version specified - just a package name
	return strings.TrimSpace(line), ""
}
