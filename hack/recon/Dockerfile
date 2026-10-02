# Recon instance for jenkins-bench M0, and the image hack/e2e boots.
#
# Plugins are pinned to "latest compatible with this LTS" rather than exact
# versions: the point of the spike is to see what a current, realistically
# configured controller exposes, and pinning would freeze that picture.
FROM jenkins/jenkins:lts

USER root
RUN apt-get update && apt-get install -y --no-install-recommends jq && rm -rf /var/lib/apt/lists/*
USER jenkins

# configuration-as-code    — deterministic setup, no wizard
# matrix-auth              — a real authorization strategy with per-user grants
# workflow-aggregator      — Pipeline, incl. workflow-multibranch and workflow-cps
# cloudbees-folder         — nested jobs, so fullName paths are exercised
# credentials-binding      — credentials referenced from a pipeline
# audit-trail              — the plugin a "build environment is logged" control looks for
# git                      — an SCM to point a Jenkinsfile at
#
# The rest exist for hack/e2e, which needs the shapes the audit of v0.1 found
# the fetcher misreading, written by the plugins themselves rather than by hand:
# generic-webhook-trigger       — a token that starts a build with no Jenkins login
# inline-pipeline               — a multibranch project whose script lives on the controller
# pipeline-multibranch-defaults — the same, with the script in a Config File Provider file
# groovy                        — a freestyle "System Groovy" step, which runs on the controller
# maven-plugin                  — a Maven job, whose config.xml root is maven2-moduleset
RUN jenkins-plugin-cli --plugins \
    configuration-as-code \
    job-dsl \
    matrix-auth \
    workflow-aggregator \
    cloudbees-folder \
    credentials-binding \
    audit-trail \
    git \
    generic-webhook-trigger \
    inline-pipeline \
    pipeline-multibranch-defaults \
    groovy \
    maven-plugin

# Skip the setup wizard: JCasC owns the configuration.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG=/var/jenkins_conf/casc.yaml
