package jenkins

import (
	"reflect"
	"testing"

	"github.com/scm-bench/jenkins-bench/internal/ci"
)

func TestFindScriptsByShape(t *testing.T) {
	cases := map[string]struct {
		config string
		want   []ci.Script
	}{
		// What the groovy plugin wrote on 2.580.1 for the e2e fixture.
		"system groovy": {`<?xml version="1.1" encoding="UTF-8"?><project><builders>
			<hudson.plugins.groovy.SystemGroovy plugin="groovy@537.v741a_5a_f1b_581">
			<source class="hudson.plugins.groovy.StringSystemScriptSource"><script plugin="script-security@1429.v0810f1b_530f5">
			<script>println &quot;x&quot;</script><sandbox>false</sandbox><classpath/></script></source><bindings></bindings>
			</hudson.plugins.groovy.SystemGroovy></builders></project>`,
			[]ci.Script{{Holder: "hudson.plugins.groovy.SystemGroovy", Sandbox: false}}},
		"groovy postbuild": {`<project><publishers><org.jvnet.hudson.plugins.groovypostbuild.GroovyPostbuildRecorder>
			<script><script>manager.addBadge()</script><sandbox>true</sandbox></script><behavior>0</behavior>
			</org.jvnet.hudson.plugins.groovypostbuild.GroovyPostbuildRecorder></publishers></project>`,
			[]ci.Script{{Holder: "org.jvnet.hudson.plugins.groovypostbuild.GroovyPostbuildRecorder", Sandbox: true}}},
		"active choices": {`<project><properties><hudson.model.ParametersDefinitionProperty><parameterDefinitions>
			<org.biouno.unochoice.ChoiceParameter><script class="org.biouno.unochoice.model.GroovyScript">
			<secureScript><script>return ["a"]</script><sandbox>false</sandbox></secureScript>
			<secureFallbackScript><script>return []</script><sandbox>true</sandbox></secureFallbackScript>
			</script></org.biouno.unochoice.ChoiceParameter></parameterDefinitions></hudson.model.ParametersDefinitionProperty></properties></project>`,
			[]ci.Script{
				{Holder: "org.biouno.unochoice.ChoiceParameter", Sandbox: false},
				{Holder: "org.biouno.unochoice.ChoiceParameter", Sandbox: true},
			}},
		"job dsl": {`<project><builders><javaposse.jobdsl.plugin.ExecuteDslScripts plugin="job-dsl@1.93">
			<scriptText>job("x")</scriptText><usingScriptText>true</usingScriptText><sandbox>false</sandbox>
			</javaposse.jobdsl.plugin.ExecuteDslScripts></builders></project>`,
			[]ci.Script{{Holder: "javaposse.jobdsl.plugin.ExecuteDslScripts", Sandbox: false}}},
		// A "sandbox" that means a test environment, with no script beside it.
		"unrelated sandbox": {`<project><publishers><com.example.PaymentDeploy><sandbox>false</sandbox><target>prod</target>
			</com.example.PaymentDeploy></publishers></project>`, nil},
		// The definition's and the factory's scripts are the job's definition,
		// read elsewhere.
		"pipeline definition": {`<flow-definition><definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
			<script>x</script><sandbox>false</sandbox></definition></flow-definition>`, nil},
		"multibranch factory": {`<org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>
			<factory class="org.jenkinsci.plugins.inlinepipeline.InlineDefinitionBranchProjectFactory"><script>x</script><sandbox>false</sandbox></factory>
			</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := findScripts([]byte(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("scripts = %+v, want %+v", got, tc.want)
			}
		})
	}
	if _, err := findScripts([]byte(`<project><unclosed>`)); err == nil {
		t.Error("a document that does not parse must be an error")
	}
}
