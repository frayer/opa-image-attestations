# opa-image-attestations

![opa test](https://github.com/frayer/opa-image-attestations/actions/workflows/opa-test.yml/badge.svg)

An experimental [Open Policy Agent](https://www.openpolicyagent.org/) policy to
test ideas around how to verify one or more attestations exist on a Container
Image before allowing that Container to run in a Kubernetes environment.
Ultimately it could be a policy that executes using the [OPA Admission
Controller](https://www.openpolicyagent.org/docs/latest/kubernetes-introduction/)
Kubernetes integration.
