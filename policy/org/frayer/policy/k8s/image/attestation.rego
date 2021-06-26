package org.frayer.policy.k8s.image

import data.kubernetes

deny[message] {
	count(validated_oneOf_attestations) == 0
	count(unvalidated_allOf_attestations) > 0

	some unvalidated_attestation; unvalidated_allOf_attestations[unvalidated_attestation]
	message := sprintf("%s is missing attestation: %s", [unvalidated_attestation.image, unvalidated_attestation.missingAttestations[_]])
}

validated_oneOf_attestations[contains] {
	some policy_to_enforce, validated_image_attestation
	policies_to_enforce[policy_to_enforce].image == validated_image_attestations[validated_image_attestation].image

	some attestation
	policy_to_enforce.oneOf[attestation] == validated_image_attestation.attestations[_]

	contains := {
		"image": policy_to_enforce.image,
		"attestation": policy_to_enforce.oneOf[attestation],
	}
}

unvalidated_allOf_attestations[missing] {
	some policy_to_enforce, validated_image_attestation
	policies_to_enforce[policy_to_enforce].image == validated_image_attestations[validated_image_attestation].image

	missing_attestations := (policy_to_enforce.allOf - validated_image_attestation.attestations)
	count(missing_attestations) > 0

	missing := {
		"image": policies_to_enforce[policy_to_enforce].image,
		"missingAttestations": { att | att := missing_attestations[_] },
		"enforcingPolicy": policy_to_enforce.enforcingPolicy
	}
}

validated_image_attestations[validated] {
	image := images[_]
	claims_jwt := input.request.object.metadata.annotations["policy.frayer.org/container-image-claims-jwt"]
	attestations := claims_jwt["frayer.org/policy/v1/container-image-attestations"]
	some attestation
	attestation_image = fully_qualified_image_name(attestations[attestation]["image-reference"], attestations[attestation]["image-digest"])
	image == attestation_image
	validated := {
		"image": image,
		"attestations": { att | att := attestations[attestation].attestations[_] }
	}
}

policies_to_enforce[policy_to_enforce] {
	namespace := input.request.object.metadata.namespace
	policy := kubernetes.attestationpolicies[namespace][_]
	image := images[_]

	regex.match(policy.spec.imagePatternMatch[_], image)
	ignored := { ignoredImage |
		regex.match(policy.spec.imagePatternIgnore[_], image)
		ignoredImage := image
	}
	count(ignored) == 0
	policy_to_enforce := {
		"enforcingPolicy": policy.metadata.name,
		"image": image,
		"trustedAttestationAuthority": policy.spec.trustedAttestationAuthority,
		"allOf": { att | att := policy.spec.requiredAttestations.allOf[_] },
		"oneOf": { att | att := policy.spec.requiredAttestations.oneOf[_] },
	}
}

images[image] {
	input.request.kind.kind == "Pod"
	image := input.request.object.spec.containers[_].image
}

fully_qualified_image_name(reference, digest) = name {
	name := concat(":", [reference, digest])
}
