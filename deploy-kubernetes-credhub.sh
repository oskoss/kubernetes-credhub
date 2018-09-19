#!/bin/bash

echo "Deploying kubernetes-credhub webhook, and controller.

kubectl is required
base64 is required
Ensure kubectl is logged in with a user that has permission to deploy
deployments, MutatingWebhookConfigurations, and services.


"
namespace=kubernetes-credhub

if [ ! -x "$(command -v base64)" ]; then
    echo "base64 not found"
    exit 1
fi

if [ ! -x "$(command -v kubectl)" ]; then
    echo "kubectl not found"
    exit 1
fi


ca_bundle=$(kubectl get configmap -n kube-system extension-apiserver-authentication -o=jsonpath='{.data.client-ca-file}' | base64 | tr -d '\n')

cat << EOF > webhook.yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: kubernetes-credhub-webhook-cfg
  labels:
    app: kubernetes-credhub-injector
webhooks:
  - name: kubernetes-credhub-injector.pivotal.io
    clientConfig:
      service:
        name: kubernetes-credhub-svc
        namespace: ${namespace}
        path: "/mutate"
      caBundle: ${ca_bundle}
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
EOF

kubectl -n ${namespace} delete -f rbac.yaml
kubectl -n ${namespace} delete -f webhook.yaml
kubectl -n ${namespace} delete -f service.yaml
kubectl -n ${namespace} delete -f deployment.yaml
kubectl -n ${namespace} create -f rbac.yaml
kubectl -n ${namespace} create -f webhook.yaml
kubectl -n ${namespace} create -f service.yaml
kubectl -n ${namespace} create -f deployment.yaml