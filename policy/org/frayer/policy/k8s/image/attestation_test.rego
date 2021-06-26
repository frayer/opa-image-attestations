package org.frayer.policy.k8s.image

attestationpolicies = {
	"default": {
		"enabled-policy": {
			"metadata": {"name": "enabled-policy"},
			"spec": {
				"trustedAttestationAuthority": "managed-supply-chain",
				"requiredAttestations": {
					"allOf": [
						"frayer.org/policy/v1/attestations/code/secrets-scan",
						"frayer.org/policy/v1/attestations/code/provenance",
						"frayer.org/policy/v1/attestations/app/iast-scan",
					],
					"oneOf": ["frayer.org/policy/v1/attestations/exception/allow"],
				},
				"imagePatternMatch": ["^.*$"],
				"imagePatternIgnore": [
					"^mysql.*$",
					"^trusted-domain.io/.*$",
				],
			},
		},
		"additive-policy": {
			"metadata": {"name": "additive-policy"},
			"spec": {
				"trustedAttestationAuthority": "managed-supply-chain",
				"requiredAttestations": {
					"allOf": [
						"frayer.org/policy/v1/attestations/code/secrets-scan-2",
						"frayer.org/policy/v1/attestations/app/iast-scan-2",
					],
					"oneOf": ["frayer.org/policy/v1/attestations/exception/allow"],
				},
				"imagePatternMatch": ["^.*$"],
				"imagePatternIgnore": [
					"^mysql.*$",
					"^trusted-domain.io/.*$",
				],
			},
		},
	}
}

jwt_payload_oneOf_attestation := {
	"sub": "apps/v1/Deployment/my-namespace/my-deployment",
	"frayer.org/policy/v1/container-image-attestations": [
		{
			"image-reference": "nginx",
			"image-digest": "latest",
			"attestations": [
				"frayer.org/policy/v1/attestations/exception/allow",
			]
		},
	],
}

jwt_payload_allOf_attestations:= {
	"sub": "apps/v1/Deployment/my-namespace/my-deployment",
	"frayer.org/policy/v1/container-image-attestations": [
		{
			"image-reference": "nginx",
			"image-digest": "latest",
			"attestations": [
				"frayer.org/policy/v1/attestations/code/secrets-scan",
				"frayer.org/policy/v1/attestations/code/secrets-scan-2",
				"frayer.org/policy/v1/attestations/code/provenance",
				"frayer.org/policy/v1/attestations/app/iast-scan",
				"frayer.org/policy/v1/attestations/app/iast-scan-2",
			]
		},
	],
}

jwt_payload_missing_attestation := {
	"sub": "apps/v1/Deployment/my-namespace/my-deployment",
	"frayer.org/policy/v1/container-image-attestations": [
		{
			"image-reference": "nginx",
			"image-digest": "latest",
			"attestations": [
				"frayer.org/policy/v1/attestations/code/secrets-scan",
				"frayer.org/policy/v1/attestations/code/provenance",
			]
		},
	],
}

create_pod_admission_review(namespace, image_claims_jwt, container_images) = ar {
	ar := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {
					"namespace": namespace,
					"annotations": {"policy.frayer.org/container-image-claims-jwt": image_claims_jwt},
					"name": "myapp",
				},
				"spec": {"containers": [ container | container := { "image": container_images[_] } ] },
			},
		},
	}
}

test_policy_to_enforce {
	admission_review := create_pod_admission_review("default", jwt_payload_missing_attestation, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	policies := policies_to_enforce with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	count(policies) == 2
	policies[{
		"enforcingPolicy": "enabled-policy",
		"image": "nginx:latest",
		"trustedAttestationAuthority": "managed-supply-chain",
		"allOf": {
			"frayer.org/policy/v1/attestations/code/secrets-scan",
			"frayer.org/policy/v1/attestations/code/provenance",
			"frayer.org/policy/v1/attestations/app/iast-scan",
		},
		"oneOf": { "frayer.org/policy/v1/attestations/exception/allow" },
	}]
	policies[{
		"enforcingPolicy": "additive-policy",
		"image": "nginx:latest",
		"trustedAttestationAuthority": "managed-supply-chain",
		"allOf": {
			"frayer.org/policy/v1/attestations/code/secrets-scan-2",
			"frayer.org/policy/v1/attestations/app/iast-scan-2",
		},
		"oneOf": { "frayer.org/policy/v1/attestations/exception/allow" },
	}]
}

test_validated_image_attestations {
	admission_review := create_pod_admission_review("default", jwt_payload_missing_attestation, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	validated := validated_image_attestations with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	trace(sprintf("%v", [validated]))
	count(validated) == 1
	some i
	validated[i].image == "nginx:latest"
	count(validated[i].attestations) == 2
}

test_validated_oneOf_attestations {
	admission_review := create_pod_admission_review("default", jwt_payload_oneOf_attestation, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	oneOf_attestations := validated_oneOf_attestations with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	trace(sprintf("%v", [oneOf_attestations]))
	count(oneOf_attestations) == 1
	oneOf_attestations[{
		"image": "nginx:latest",
		"attestation": "frayer.org/policy/v1/attestations/exception/allow"
	}]
}

test_unvalidated_allOf_attestations {
	admission_review := create_pod_admission_review("default", jwt_payload_missing_attestation, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	missing := unvalidated_allOf_attestations with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	trace(sprintf("%v", [missing]))
	count(missing) == 2
	missing[
		{
			"enforcingPolicy": "enabled-policy",
			"image": "nginx:latest",
			"missingAttestations": {"frayer.org/policy/v1/attestations/app/iast-scan"},
		}
	]
	missing[
		{
			"enforcingPolicy": "additive-policy",
			"image": "nginx:latest",
			"missingAttestations": {
				"frayer.org/policy/v1/attestations/code/secrets-scan-2",
				"frayer.org/policy/v1/attestations/app/iast-scan-2"
			},
		}
	]
}

test_deny_with_oneOf_attestation {
	admission_review := create_pod_admission_review("default", jwt_payload_oneOf_attestation, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	denied := deny with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	count(denied) == 0
}

test_deny_with_allOf_attestation {
	admission_review := create_pod_admission_review("default", jwt_payload_allOf_attestations, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	denied := deny with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	count(denied) == 0
}

test_deny_with_missing_attestation {
	admission_review := create_pod_admission_review("default", jwt_payload_missing_attestation, ["nginx:latest", "mysql:8", "trusted-domain.io/my-image:1.0"])

	denied := deny with input as admission_review with data.kubernetes.attestationpolicies as attestationpolicies
	trace(sprintf("%v", [denied]))
	count(denied) == 3
	denied["nginx:latest is missing attestation: frayer.org/policy/v1/attestations/code/secrets-scan-2"]
	denied["nginx:latest is missing attestation: frayer.org/policy/v1/attestations/app/iast-scan"]
	denied["nginx:latest is missing attestation: frayer.org/policy/v1/attestations/app/iast-scan-2"]
}
