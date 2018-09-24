#!/bin/bash

echo "We will deploy the kubernetes-credhub webhook, and controller to K8s.

This involves:
 - Building 2 containers (with your credhub credentials compiled in)
 - Pushing the containers to a container registry
 - Deploying Kubernetes MutatingWebhookConfigurations, Deployments, and Services

kubectl is required
docker is required
base64 is required

Ensure kubectl is logged in with a user that has permission to deploy
deployments, MutatingWebhookConfigurations, and services.

Ensure docker is logged in and you can push to dockerhub under the 
provided tag.

Hit ANY KEY when all the above are met and you are ready to go!

"
while get



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