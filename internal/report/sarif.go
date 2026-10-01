package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/console"
	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// SARIF 2.1.0. Findings here are configuration facts about a controller rather
// than lines of source, so each result names its job or the controller as a
// logicalLocation — and also carries a physicalLocation, because GitHub code
// scanning drops any result without one: the upload reports success and the
// Security tab stays empty, which a pipeline reads as nothing to fix
// (scm-bench/jenkins-bench#10). The artifact URI is a stable path naming the
// controller and the resource; it need not exist in the repository the SARIF
// is uploaded to, as OpenSSF Scorecard's do not.

const (
	sarifVersion = "2.1.0"
	// The old master/Schemata/ path 404s — oasis-tcs renamed the default branch
	// and restructured the repository. A $schema that does not resolve is not
	// cosmetic: a validating consumer fetches it, and every report we emit
	// carries the URL.
	sarifSchema   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifInfoURI  = "https://github.com/scm-bench/jenkins-bench"
	sarifToolName = "jenkins-bench"

	// maxSARIFResults is GitHub's cap on what it keeps from one run: past
	// 5,000 it keeps the most severe 5,000, past 25,000 it rejects the file —
	// and a 10,000-job controller produces some 30,000 results. Capping here,
	// most severe first, makes which ones survive our choice and lets the run
	// say how many it withheld.
	maxSARIFResults = 5000

	// manualRuleSuffix marks the rule a MANUAL result points at.
	manualRuleSuffix = "/manual"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool              `json:"tool"`
	AutomationDetails *sarifAutomationDetail `json:"automationDetails,omitempty"`
	Results           []sarifResult          `json:"results"`
	Invocations       []sarifInvocation      `json:"invocations,omitempty"`
	Properties        map[string]any         `json:"properties,omitempty"`
}

// sarifAutomationDetail identifies the run's category. Without one, two
// controllers uploading to the same GitHub repository share a category, and
// each upload closes the other's alerts as fixed.
type sarifAutomationDetail struct {
	ID string `json:"id"`
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
	// SecuritySeverity is the 0-10 numeric score GitHub code scanning takes an
	// alert's displayed severity from. Absent on a MANUAL rule.
	SecuritySeverity string `json:"security-severity,omitempty"`
	Severity         string `json:"severity,omitempty"`
	CISID            string `json:"cisId,omitempty"`
	Automated        bool   `json:"automated"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion is required by GitHub alongside the artifact; a configuration
// finding has no line, so it is the artifact's first character.
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
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

// place is where a run's results live: the platform and the controller.
type place struct {
	platform string
	host     string
}

func writeSARIF(w io.Writer, rep *engine.Report, opts Options) error {
	where := place{platform: platformOf(rep), host: controllerHost(rep.Metadata.BaseURL)}
	rules := map[string]sarifRule{}
	// Not `var results []sarifResult`: a nil slice marshals to null, and
	// run.results is typed `array` in the SARIF schema. Strict validators and
	// GitHub's SARIF upload reject the file outright — and they would do it on
	// the one run where nothing failed, which is precisely the run an operator
	// least expects to be told their report is malformed.
	results := []sarifResult{}

	// A control no API can answer is one question for a person, however many
	// jobs it spans: one result per control, anchored at the controller. Per
	// job, a thousand-job controller sent thousands of identical "manual
	// review" results toward GitHub's cap.
	byDesign := map[string][]engine.Finding{}
	var designOrder []string

	for _, f := range rep.Findings {
		// PASS and NA are not emitted: code scanning shows alerts, and
		// neither is one.
		if f.Status != engine.StatusFail && f.Status != engine.StatusManual {
			continue
		}
		if f.Status == engine.StatusManual && !f.Automated {
			if _, seen := byDesign[f.CheckID]; !seen {
				designOrder = append(designOrder, f.CheckID)
			}
			byDesign[f.CheckID] = append(byDesign[f.CheckID], f)
			continue
		}
		rule := buildRule(f)
		rules[rule.ID] = rule
		results = append(results, buildResult(f, where))
	}
	for _, id := range designOrder {
		group := byDesign[id]
		rule := buildRule(group[0])
		rules[rule.ID] = rule
		results = append(results, buildAggregateResult(group, where))
	}

	// Most severe first, so the cap keeps what matters; then stable.
	sort.SliceStable(results, func(i, j int) bool {
		if a, b := resultRank(results[i]), resultRank(results[j]); a != b {
			return a > b
		}
		return results[i].RuleID+"\x00"+results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI <
			results[j].RuleID+"\x00"+results[j].Locations[0].PhysicalLocation.ArtifactLocation.URI
	})
	withheld := 0
	if len(results) > maxSARIFResults {
		withheld = len(results) - maxSARIFResults
		results = results[:maxSARIFResults]
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           sarifToolName,
			Version:        opts.ToolVersion,
			InformationURI: sarifInfoURI,
			Rules:          ruleList,
		}},
		AutomationDetails: &sarifAutomationDetail{ID: sarifToolName + "/" + where.host + "/"},
		Results:           results,
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
	// A run with no job to judge produces a SARIF file with no job results —
	// which a code-scanning dashboard shows as every job alert fixed.
	if rep.Coverage.NoJobsAudited() {
		notifications = append(notifications, sarifNotification{Level: "error", Message: sarifText{
			Text: "No job was evaluated, so nothing job-scope was audited; a token without Job/Read is shown an empty job list.",
		}})
	}
	// Likewise a folder that could not be listed: its jobs are absent from
	// the results, and absence is what a fixed alert looks like. The folders
	// themselves are already named among the scan warnings above.
	if !rep.Coverage.Complete {
		text := "The snapshot does not record its job list as complete, so jobs may be missing from these results."
		if n := len(rep.Coverage.Unlisted); n > 0 {
			text = fmt.Sprintf("The job list is incomplete: %s could not be listed, and the jobs in them were not evaluated.",
				console.Pluralize(n, "container"))
		}
		notifications = append(notifications, sarifNotification{Level: "error", Message: sarifText{Text: text}})
	}
	if withheld > 0 {
		notifications = append(notifications, sarifNotification{Level: "warning", Message: sarifText{Text: fmt.Sprintf(
			"%d less severe results were withheld to stay within code scanning's %d-result limit; -o json carries every finding",
			withheld, maxSARIFResults)}})
	}
	run.Invocations = []sarifInvocation{{
		ExecutionSuccessful:        len(rep.Errors) == 0 && !rep.Coverage.NoJobsAudited() && rep.Coverage.Complete,
		ToolExecutionNotifications: notifications,
	}}

	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

// controllerHost is the controller's host and port, the stable part of every
// artifact URI and of the run's category.
func controllerHost(baseURL string) string {
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return engine.InstanceResourceName
}

func platformOf(rep *engine.Report) string {
	if rep.Metadata.Platform != "" {
		return rep.Metadata.Platform
	}
	return "jenkins"
}

// artifactURI names a resource as a relative path — platform, controller,
// then the job's full name — one escaped segment each, so a folder or job
// whose name holds a space, a slash-encoded branch or non-ASCII stays one
// unambiguous segment.
func artifactURI(where place, resource string) string {
	segments := []string{url.PathEscape(where.platform), url.PathEscape(where.host)}
	for _, part := range strings.Split(resource, "/") {
		segments = append(segments, url.PathEscape(part))
	}
	return strings.Join(segments, "/")
}

// resultRank orders results for the cap: real failures by severity, then
// everything that only needs a person.
func resultRank(r sarifResult) int {
	if strings.HasSuffix(r.RuleID, manualRuleSuffix) {
		return 0
	}
	switch r.Level {
	case "error":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func buildRule(f engine.Finding) sarifRule {
	helpURI := ""
	if len(f.References) > 0 {
		helpURI = f.References[0]
	}
	// SARIF distinguishes the two: shortDescription is the label a viewer puts
	// in a list, fullDescription is what it shows when the reader wants to know
	// what the rule is about.
	full := f.Description
	if strings.TrimSpace(full) == "" {
		full = f.Title
	}

	rule := sarifRule{
		ID:                   f.CheckID,
		Name:                 strings.ReplaceAll(f.CheckID, "-", ""),
		ShortDescription:     sarifText{Text: f.Title},
		FullDescription:      sarifText{Text: full},
		Help:                 sarifText{Text: f.Remediation},
		HelpURI:              helpURI,
		DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(f.Severity)},
		Properties: sarifRuleProperty{
			Tags:             []string{"security", "supply-chain", "cis", "build-pipelines"},
			SecuritySeverity: securitySeverity(f.Severity),
			Severity:         strings.ToUpper(f.Severity),
			CISID:            f.CISID,
			Automated:        f.Automated,
		},
	}
	// A MANUAL result points at a rule of its own, with no security-severity.
	// GitHub takes an alert's displayed severity from the rule, not the
	// result, so sharing the control's rule made "a person needs to check
	// this" display at the control's severity — and a control that can only
	// be MANUAL, like CIS-2.2.1, display as High on every run.
	if f.Status == engine.StatusManual {
		rule.ID += manualRuleSuffix
		rule.Name += "Manual"
		rule.ShortDescription = sarifText{Text: "Manual review: " + f.Title}
		rule.DefaultConfiguration = sarifRuleConfig{Level: "note"}
		rule.Properties.SecuritySeverity = ""
		rule.Properties.Tags = append(rule.Properties.Tags, "manual-review")
	}
	return rule
}

func buildResult(f engine.Finding, where place) sarifResult {
	level := sarifLevel(f.Severity)
	ruleID := f.CheckID
	if f.Status == engine.StatusManual {
		// A control nobody could evaluate is not an assertion that something
		// is broken, so it never escalates past a note.
		level = "note"
		ruleID += manualRuleSuffix
	}

	message := f.Details
	if f.Status == engine.StatusManual {
		message = "Manual review required: " + message
	}
	if fix := f.Remediation; fix != "" {
		message += "\n\nRemediation: " + fix
	}

	return sarifResult{
		RuleID:    ruleID,
		Level:     level,
		Message:   sarifText{Text: message},
		Locations: []sarifLocation{location(where, f.Resource, f.ResourceType)},
		// Fingerprinting on control plus resource lets a consumer track the
		// same finding across runs even as wording changes. GitHub reads
		// primaryLocationLineHash, keyed on the controller too, so two
		// controllers' findings never merge; scmBenchFindingV1 is the
		// family's own key, unchanged.
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint(where.host, f.CheckID, f.Resource) + ":1",
			"scmBenchFindingV1":       fingerprint(f.CheckID, f.Resource),
		},
		Properties: map[string]any{
			"status":       string(f.Status),
			"severity":     strings.ToUpper(f.Severity),
			"cisId":        f.CISID,
			"resourceType": f.ResourceType,
		},
	}
}

// buildAggregateResult is the one result for a control no API can answer,
// naming how many resources it covers and anchored at the controller.
func buildAggregateResult(group []engine.Finding, where place) sarifResult {
	f := group[0]
	anchor := f
	anchor.Resource = engine.InstanceResourceName
	anchor.ResourceType = engine.ResourceController
	result := buildResult(anchor, where)
	if len(group) > 1 || f.ResourceType != engine.ResourceController {
		result.Message.Text = fmt.Sprintf("Manual review required for %s: %s", console.Pluralize(len(group), f.ResourceType), f.Details)
		if fix := f.Remediation; fix != "" {
			result.Message.Text += "\n\nRemediation: " + fix
		}
	}
	result.Properties["resources"] = len(group)
	return result
}

func location(where place, resource, kind string) sarifLocation {
	return sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: artifactURI(where, resource)},
			Region:           sarifRegion{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 1},
		},
		LogicalLocations: []sarifLogicalLocation{{
			Name:               resource,
			FullyQualifiedName: resource,
			Kind:               kind,
		}},
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
		return "2.0"
	}
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}
