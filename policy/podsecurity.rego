package k8s.podsecurity

import rego.v1

# ---------------------------------------------------------------------------
# Normalize the pod spec location. A bare Pod has it at spec; Deployments,
# StatefulSets, DaemonSets, and Jobs nest it under spec.template.spec;
# CronJobs nest it one level deeper still.
# ---------------------------------------------------------------------------

default pod_spec := {}

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

all_containers := array.concat(
	object.get(pod_spec, "containers", []),
	object.get(pod_spec, "initContainers", []),
)

approved_registries := {
	"registry.internal.example.com/",
	"gcr.io/my-org-project/",
}

allowed_environments := {"dev", "staging", "prod"}

# ---------------------------------------------------------------------------
# POL-001 — No privileged containers
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	c.securityContext.privileged == true
	msg := sprintf("POL-001: container '%s' must not run privileged", [c.name])
}

# ---------------------------------------------------------------------------
# POL-002 — Containers must not run as root
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	not container_runs_as_nonroot(c)
	msg := sprintf("POL-002: container '%s' must set runAsNonRoot true (pod or container level)", [c.name])
}

container_runs_as_nonroot(c) if c.securityContext.runAsNonRoot == true

container_runs_as_nonroot(c) if pod_spec.securityContext.runAsNonRoot == true

# ---------------------------------------------------------------------------
# POL-003 — CPU and memory limits required
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	not c.resources.limits.cpu
	msg := sprintf("POL-003: container '%s' is missing a CPU limit", [c.name])
}

deny contains msg if {
	some c in all_containers
	not c.resources.limits.memory
	msg := sprintf("POL-003: container '%s' is missing a memory limit", [c.name])
}

# ---------------------------------------------------------------------------
# POL-004 — No ':latest' image tag
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	endswith(c.image, ":latest")
	msg := sprintf("POL-004: container '%s' uses the ':latest' tag", [c.name])
}

deny contains msg if {
	some c in all_containers
	not contains(c.image, ":")
	not contains(c.image, "@sha256:")
	msg := sprintf("POL-004: container '%s' image has no explicit tag or digest", [c.name])
}

# ---------------------------------------------------------------------------
# POL-005 — Images must come from an approved registry
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	not image_from_approved_registry(c.image)
	msg := sprintf("POL-005: container '%s' image '%s' is not from an approved registry", [c.name, c.image])
}

image_from_approved_registry(image) if {
	some prefix in approved_registries
	startswith(image, prefix)
}

# ---------------------------------------------------------------------------
# POL-006 — No host namespace sharing
# ---------------------------------------------------------------------------

deny contains msg if {
	pod_spec.hostNetwork == true
	msg := "POL-006: hostNetwork must not be enabled"
}

deny contains msg if {
	pod_spec.hostPID == true
	msg := "POL-006: hostPID must not be enabled"
}

deny contains msg if {
	pod_spec.hostIPC == true
	msg := "POL-006: hostIPC must not be enabled"
}

# ---------------------------------------------------------------------------
# POL-007 — No hostPath volumes
# ---------------------------------------------------------------------------

deny contains msg if {
	some v in object.get(pod_spec, "volumes", [])
	v.hostPath
	msg := sprintf("POL-007: volume '%s' must not use hostPath", [v.name])
}

# ---------------------------------------------------------------------------
# POL-008 — Required labels
# ---------------------------------------------------------------------------

deny contains msg if {
	not input.metadata.labels.team
	msg := "POL-008: missing required label 'team'"
}

deny contains msg if {
	not input.metadata.labels.environment
	msg := "POL-008: missing required label 'environment'"
}

deny contains msg if {
	env := input.metadata.labels.environment
	env != ""
	not env in allowed_environments
	msg := sprintf("POL-008: label 'environment' value '%s' must be one of dev/staging/prod", [env])
}

# ---------------------------------------------------------------------------
# POL-009 — Read-only root filesystem
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("POL-009: container '%s' must set readOnlyRootFilesystem true", [c.name])
}

# ---------------------------------------------------------------------------
# POL-010 — No default namespace
# ---------------------------------------------------------------------------

deny contains msg if {
	ns := object.get(input.metadata, "namespace", "default")
	ns == "default"
	msg := "POL-010: workloads must not deploy to the 'default' namespace"
}
