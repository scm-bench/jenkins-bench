package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// SARIF 2.1.0. Findings here are configuration facts about a controller rather
// than lines of source, so each result carries a logicalLocation naming the
// controller instead of a physicalLocation pointing into a file that does not
// exist.

const (
	sarifVersion = "2.1.0"
	// The old master/Schemata/ path 404s — oasis-tcs renamed the default branch
	// and restructured the repository. A $schema that does not resolve is not
	// cosmetic: a validating consumer fetches it, and every report we emit
	// carries the URL.
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifInfoURI = "https://github.com/scm-bench/jenkins-bench"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	// No omitempty on these two: it does nothing on a struct, and both are
	// always populated anyway — fullDescription falls back to the title, and
	// remediation is required of every control.
	FullDescription      sarifText         `json:"fullDescription"`
	Help                 sarifText         `json:"help"`
	HelpURI              string            `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig   `json:"defaultConfiguration"`
	Properties           sarifRuleProperty `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperty struct {
	Tags []string `json:"tags,omitempty"`
	// SecuritySeverity is the 0-10 numeric score consumers such as GitHub code
	// scanning use to bucket findings.
	SecuritySeverity string `json:"security-severity,omitempty"`
	Severity         string `json:"severity,omitempty"`
	CISID            string `json:"cisId,omitempty"`
	Automated        bool   `json:"automated"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

func writeSARIF(w io.Writer, rep *engine.Report, opts Options) error {
	rules := map[string]sarifRule{}
	// Not `var results []sarifResult`: a nil slice marshals to null, and
	// run.results is typed `array` in the SARIF schema. Strict validators and
	// GitHub's SARIF upload reject the file outright — and they would do it on
	// the one run where nothing failed, which is precisely the run an operator
	// least expects to be told their report is malformed.
	results := []sarifResult{}

	for _, f := range rep.Findings {
		// NA findings are noise in a CI report: the control does not apply.
		// PASS is omitted for the same reason SARIF consumers expect only
		// actionable results.
		if f.Status != engine.StatusFail && f.Status != engine.StatusManual {
			continue
		}
		if _, ok := rules[f.CheckID]; !ok {
			rules[f.CheckID] = buildRule(f)
		}
		// A rule that turns out to have a real failure is escalated back to its
		// own severity. See demoteToNote for why it starts below it.
		if f.Status == engine.StatusFail {
			rule := rules[f.CheckID]
			rule.DefaultConfiguration.Level = sarifLevel(f.Severity)
			rule.Properties.SecuritySeverity = securitySeverity(f.Severity)
			rules[f.CheckID] = rule
		}
		results = append(results, buildResult(f))
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "jenkins-bench",
			Version:        opts.ToolVersion,
			InformationURI: sarifInfoURI,
			Rules:          ruleList,
		}},
		Results: results,
		Properties: map[string]any{
			"score":    rep.Score.Value,
			"passed":   rep.Score.Passed,
			"failed":   rep.Score.Failed,
			"manual":   rep.Score.Manual,
			"platform": rep.Metadata.Platform,
			"baseUrl":  rep.Metadata.BaseURL,
		},
	}

	// Scan warnings and policy errors travel as invocation notifications so a
	// partial scan is not mistaken for a clean one.
	var notifications []sarifNotification
	for _, warning := range rep.Metadata.Warnings {
		notifications = append(notifications, sarifNotification{Level: "warning", Message: sarifText{Text: warning}})
	}
	for _, e := range rep.Errors {
		notifications = append(notifications, sarifNotification{Level: "error", Message: sarifText{Text: e}})
	}
	run.Invocations = []sarifInvocation{{
		ExecutionSuccessful:        len(rep.Errors) == 0,
		ToolExecutionNotifications: notifications,
	}}

	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func buildRule(f engine.Finding) sarifRule {
	helpURI := ""
	if len(f.References) > 0 {
		helpURI = f.References[0]
	}
	// SARIF distinguishes the two: shortDescription is the label a viewer puts
	// in a list, fullDescription is what it shows when the reader wants to know
	// what the rule is about. Repeating the title in both, as this did before
	// the control's description was carried on the finding, wasted the field.
	full := f.Description
	if strings.TrimSpace(full) == "" {
		full = f.Title
	}

	// The rule starts at note and is raised to its real severity by the caller
	// the first time an actual failure lands on it.
	//
	// GitHub takes an alert's displayed severity from the rule's
	// security-severity, not from the result's level — so a control that can
	// only ever report MANUAL, like CIS-1.3.5 for multi-factor authentication,
	// arrived in the Security panel as an 8.0 High alert saying a setting was
	// broken, while `--fail-on high` locally did not fail on it at all. Two
	// severities for the same finding, and the louder one was wrong.
	level, severity := "note", securitySeverity(checks.SeverityLow)
	if f.Status == engine.StatusFail {
		level, severity = sarifLevel(f.Severity), securitySeverity(f.Severity)
	}

	return sarifRule{
		ID:                   f.CheckID,
		Name:                 strings.ReplaceAll(f.CheckID, "-", ""),
		ShortDescription:     sarifText{Text: f.Title},
		FullDescription:      sarifText{Text: full},
		Help:                 sarifText{Text: f.Remediation},
		HelpURI:              helpURI,
		DefaultConfiguration: sarifRuleConfig{Level: level},
		Properties: sarifRuleProperty{
			Tags:             []string{"security", "supply-chain", "cis", "source-code"},
			SecuritySeverity: severity,
			Severity:         strings.ToUpper(f.Severity),
			CISID:            f.CISID,
			Automated:        f.Automated,
		},
	}
}

func buildResult(f engine.Finding) sarifResult {
	level := sarifLevel(f.Severity)
	if f.Status == engine.StatusManual {
		// A control nobody could evaluate is not an assertion that something
		// is broken, so it never escalates past a note.
		level = "note"
	}

	message := f.Details
	if f.Status == engine.StatusManual {
		message = "Manual review required: " + message
	}
	if fix := f.Remediation; fix != "" {
		message += "\n\nRemediation: " + fix
	}

	return sarifResult{
		RuleID:  f.CheckID,
		Level:   level,
		Message: sarifText{Text: message},
		Locations: []sarifLocation{{
			LogicalLocations: []sarifLogicalLocation{{
				Name:               f.Resource,
				FullyQualifiedName: f.Resource,
				Kind:               f.ResourceType,
			}},
		}},
		// Fingerprinting on control plus resource lets a consumer track the
		// same finding across runs even as wording changes.
		PartialFingerprints: map[string]string{
			"scmBenchFindingV1": fingerprint(f.CheckID, f.Resource),
		},
		Properties: map[string]any{
			"status":       string(f.Status),
			"severity":     strings.ToUpper(f.Severity),
			"cisId":        f.CISID,
			"resourceType": f.ResourceType,
		},
	}
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case checks.SeverityHigh:
		return "8.0"
	case checks.SeverityMedium:
		return "5.0"
	default:
		return "3.0"
	}
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}
