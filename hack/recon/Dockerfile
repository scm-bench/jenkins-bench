# Recon instance for jenkins-bench M0.
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
RUN jenkins-plugin-cli --plugins \
    configuration-as-code \
    job-dsl \
    matrix-auth \
    workflow-aggregator \
    cloudbees-folder \
    credentials-binding \
    audit-trail \
    git

# Skip the setup wizard: JCasC owns the configuration.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG=/var/jenkins_conf/casc.yaml
