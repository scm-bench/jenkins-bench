package jenkins

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/scm-bench/jenkins-bench/internal/ci"
)

// xmlFrame is one open element while findScripts walks a document.
type xmlFrame struct {
	name     string
	children map[string]bool
	sandbox  *string
	text     strings.Builder
}

// findScripts lists the Groovy scripts a job's configuration carries outside
// its pipeline definition, each by the class that holds it and whether
// script-security runs it in the sandbox.
//
// A freestyle job has no pipeline definition, and CIS-2.1.2 said NA for every
// one — while a System Groovy build step with its sandbox off runs on the
// controller with the controller's privileges, exactly the exposure the
// control fails an inline pipeline for (verified on 2.580.1). The same
// script-security object turns up in Groovy Postbuild publishers and Active
// Choices parameters, and Job DSL keeps the same flag beside its script, so
// they are found by shape rather than by plugin: an element holding a <sandbox>
// flag beside a <script> or <scriptText>. The flag alone is not enough —
// plenty of plugins have a "sandbox" that means a test environment.
//
// The pipeline <definition> and a multibranch <factory> are skipped: their
// scripts are read as the job's definition.
func findScripts(body []byte) ([]ci.Script, error) {
	var (
		stack   []*xmlFrame
		scripts []ci.Script
	)
	decoder := newConfigDecoder(prepareConfigXML(body))
	for {
		tok, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return scripts, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if n := len(stack); n > 0 {
				stack[n-1].children[t.Name.Local] = true
			}
			stack = append(stack, &xmlFrame{name: t.Name.Local, children: map[string]bool{}})
		case xml.CharData:
			if n := len(stack); n > 0 && stack[n-1].name == "sandbox" {
				stack[n-1].text.Write(t)
			}
		case xml.EndElement:
			n := len(stack)
			if n == 0 {
				continue
			}
			f := stack[n-1]
			stack = stack[:n-1]
			if f.name == "sandbox" && len(stack) > 0 {
				flag := strings.TrimSpace(f.text.String())
				stack[len(stack)-1].sandbox = &flag
				continue
			}
			if f.sandbox == nil || !(f.children["script"] || f.children["scriptText"]) {
				continue
			}
			if underDefinition(f, stack) {
				continue
			}
			scripts = append(scripts, ci.Script{Holder: scriptHolder(f, stack), Sandbox: *f.sandbox == "true"})
		}
	}
}

// underDefinition reports whether a frame sits in the document's <definition>
// or <factory> — itself one of them, or inside one.
func underDefinition(f *xmlFrame, ancestors []*xmlFrame) bool {
	top := f.name
	if len(ancestors) >= 2 {
		top = ancestors[1].name
	} else if len(ancestors) == 0 {
		return false
	}
	return top == "definition" || top == "factory"
}

// scriptHolder names the class a script belongs to: the nearest element,
// itself or an ancestor, named like a class — XStream writes a plugin's build
// step, publisher or parameter under its class name.
func scriptHolder(f *xmlFrame, ancestors []*xmlFrame) string {
	if strings.Contains(f.name, ".") {
		return f.name
	}
	for i := len(ancestors) - 1; i > 0; i-- {
		if strings.Contains(ancestors[i].name, ".") {
			return ancestors[i].name
		}
	}
	return f.name
}
