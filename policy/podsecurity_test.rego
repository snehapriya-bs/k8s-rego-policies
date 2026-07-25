package k8s.podsecurity_test

import rego.v1
import data.k8s.podsecurity.deny

# ---------------------------------------------------------------------------
# A fully compliant Pod. Every rule-specific test below either reuses this
# directly or builds an explicit variant that breaks exactly one thing, so
# failures are unambiguous. (Deliberately NOT using object.union to patch
# fields here — it deep-merges nested objects, so trying to "delete" a field
# by omitting it from an override silently keeps the original value instead.)
# ---------------------------------------------------------------------------

compliant_pod := {
	"kind": "Pod",
	"metadata": {
		"name": "good-pod",
		"namespace": "team-a",
		"labels": {"team": "platform", "environment": "prod"},
	},
	"spec": {
		"hostNetwork": false,
		"hostPID": false,
		"hostIPC": false,
		"volumes": [{"name": "cache", "emptyDir": {}}],
		"containers": [{
			"name": "app",
			"image": "registry.internal.example.com/app:1.4.2",
			"securityContext": {
				"privileged": false,
				"runAsNonRoot": true,
				"readOnlyRootFilesystem": true,
			},
			"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
		}],
	},
}

test_compliant_pod_has_no_violations if {
	count(deny) == 0 with input as compliant_pod
}

# ---------------------------------------------------------------------------
# POL-001 — privileged containers
# ---------------------------------------------------------------------------

test_privileged_container_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"containers": [object.union(compliant_pod.spec.containers[0], {
			"securityContext": object.union(compliant_pod.spec.containers[0].securityContext, {"privileged": true}),
		})],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-001")
}

# ---------------------------------------------------------------------------
# POL-002 — must run as non-root
# ---------------------------------------------------------------------------

test_root_container_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"containers": [object.union(compliant_pod.spec.containers[0], {
			"securityContext": object.union(compliant_pod.spec.containers[0].securityContext, {"runAsNonRoot": false}),
		})],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-002")
}

# ---------------------------------------------------------------------------
# POL-003 — resource limits required
# ---------------------------------------------------------------------------

test_missing_cpu_limit_is_denied if {
	bad := {
		"kind": "Pod",
		"metadata": compliant_pod.metadata,
		"spec": {"containers": [{
			"name": "app",
			"image": compliant_pod.spec.containers[0].image,
			"securityContext": compliant_pod.spec.containers[0].securityContext,
			"resources": {"limits": {"memory": "256Mi"}}, # cpu omitted on purpose
		}]},
	}
	some msg in deny with input as bad
	startswith(msg, "POL-003")
}

test_missing_memory_limit_is_denied if {
	bad := {
		"kind": "Pod",
		"metadata": compliant_pod.metadata,
		"spec": {"containers": [{
			"name": "app",
			"image": compliant_pod.spec.containers[0].image,
			"securityContext": compliant_pod.spec.containers[0].securityContext,
			"resources": {"limits": {"cpu": "500m"}}, # memory omitted on purpose
		}]},
	}
	some msg in deny with input as bad
	startswith(msg, "POL-003")
}

# ---------------------------------------------------------------------------
# POL-004 — no ':latest' tag / no missing tag
# ---------------------------------------------------------------------------

test_latest_tag_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"containers": [object.union(compliant_pod.spec.containers[0], {"image": "registry.internal.example.com/app:latest"})],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-004")
}

test_missing_tag_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"containers": [object.union(compliant_pod.spec.containers[0], {"image": "registry.internal.example.com/app"})],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-004")
}

# ---------------------------------------------------------------------------
# POL-005 — approved registry only
# ---------------------------------------------------------------------------

test_unapproved_registry_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"containers": [object.union(compliant_pod.spec.containers[0], {"image": "docker.io/library/app:1.4.2"})],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-005")
}

# ---------------------------------------------------------------------------
# POL-006 — no host namespace sharing
# ---------------------------------------------------------------------------

test_host_network_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {"hostNetwork": true})})
	some msg in deny with input as bad
	startswith(msg, "POL-006")
}

test_host_pid_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {"hostPID": true})})
	some msg in deny with input as bad
	startswith(msg, "POL-006")
}

# ---------------------------------------------------------------------------
# POL-007 — no hostPath volumes
# ---------------------------------------------------------------------------

test_hostpath_volume_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"volumes": [{"name": "node-fs", "hostPath": {"path": "/etc"}}],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-007")
}

# ---------------------------------------------------------------------------
# POL-008 — required labels
# ---------------------------------------------------------------------------

test_missing_team_label_is_denied if {
	bad := {
		"kind": "Pod",
		"metadata": {"name": "good-pod", "namespace": "team-a", "labels": {"environment": "prod"}},
		"spec": compliant_pod.spec,
	}
	some msg in deny with input as bad
	startswith(msg, "POL-008")
}

test_invalid_environment_label_is_denied if {
	bad := object.union(compliant_pod, {"metadata": object.union(compliant_pod.metadata, {
		"labels": {"team": "platform", "environment": "sandbox"},
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-008")
}

# ---------------------------------------------------------------------------
# POL-009 — read-only root filesystem
# ---------------------------------------------------------------------------

test_writable_root_fs_is_denied if {
	bad := object.union(compliant_pod, {"spec": object.union(compliant_pod.spec, {
		"containers": [object.union(compliant_pod.spec.containers[0], {
			"securityContext": object.union(compliant_pod.spec.containers[0].securityContext, {"readOnlyRootFilesystem": false}),
		})],
	})})
	some msg in deny with input as bad
	startswith(msg, "POL-009")
}

# ---------------------------------------------------------------------------
# POL-010 — no default namespace
# ---------------------------------------------------------------------------

test_default_namespace_is_denied if {
	bad := object.union(compliant_pod, {"metadata": object.union(compliant_pod.metadata, {"namespace": "default"})})
	some msg in deny with input as bad
	startswith(msg, "POL-010")
}

test_missing_namespace_defaults_to_denied if {
	bad := {
		"kind": "Pod",
		"metadata": {"name": "good-pod", "labels": compliant_pod.metadata.labels},
		"spec": compliant_pod.spec,
	}
	some msg in deny with input as bad
	startswith(msg, "POL-010")
}

# ---------------------------------------------------------------------------
# Deployment (nested pod spec) sanity check — same policy, different kind
# ---------------------------------------------------------------------------

test_deployment_wraps_pod_spec_correctly if {
	deployment := {
		"kind": "Deployment",
		"metadata": {"name": "good-deploy", "namespace": "team-a", "labels": {"team": "platform", "environment": "prod"}},
		"spec": {"template": {"spec": compliant_pod.spec}},
	}
	count(deny) == 0 with input as deployment
}

test_deployment_privileged_container_is_denied if {
	deployment := {
		"kind": "Deployment",
		"metadata": {"name": "bad-deploy", "namespace": "team-a", "labels": {"team": "platform", "environment": "prod"}},
		"spec": {"template": {"spec": object.union(compliant_pod.spec, {
			"containers": [object.union(compliant_pod.spec.containers[0], {
				"securityContext": object.union(compliant_pod.spec.containers[0].securityContext, {"privileged": true}),
			})],
		})}},
	}
	some msg in deny with input as deployment
	startswith(msg, "POL-001")
}
