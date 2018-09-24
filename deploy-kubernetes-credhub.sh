#!/bin/bash

echo "We will deploy the kubernetes-credhub integration.

This involves:
 - Building 2 containers (with your credhub credentials compiled in)
 - Pushing the containers to a container registry
 - Getting the K8s extension-apiserver CA
 - Create and deploy the following K8s constructs:
   - kubernetes-credhub namespace
   - kubernetes-credhub webhook
   - kubernetes-credhub CSR
   - kubernetes-credhub ServiceAccount
   - kubernetes-credhub ClusterRoleBinding
   - kubernetes-credhub service
   - kubernetes-credhub deployment (webhook and controller containers)

kubectl is required
docker is required
base64 is required
openssl is required

Ensure kubectl is logged in with a user that has permission to deploy
deployments, MutatingWebhookConfigurations, and services.

Ensure docker is logged in and you can push to dockerhub under the 
provided tag.
"

read -p "Press <ENTER> when all the above are met and you are ready to go!"

if [ ! -x "$(command -v openssl)" ]; then
    echo "openssl not found"
    exit 1
fi

if [ ! -x "$(command -v base64)" ]; then
    echo "base64 not found"
    exit 1
fi

if [ ! -x "$(command -v kubectl)" ]; then
    echo "kubectl not found"
    exit 1
fi

which docker
if [ $? -eq 0 ]
then
    docker --version | grep "Docker Version"
    if [ $? -eq 0 ]
    then
    else
        echo "docker not found"
        exit 1
    fi
else
    echo "docker not found"
    exit 1
fi



docker build --no-cache -t oskoss/kubernetes-credhub-init:v0 . && docker push oskoss/kubernetes-credhub-init:v0


ca_bundle=$(kubectl get configmap -n kube-system extension-apiserver-authentication -o=jsonpath='{.data.client-ca-file}' | base64 | tr -d '\n')


service=kubernetes-credhub-svc
namespace=kubernetes-credhub

kubectl create namespace ${namespace} && 0

csrName=${service}.${namespace}
rm -rf generatedCerts
mkdir -p generatedCerts
tmpdir=generatedCerts/
echo "creating certs in tmpdir ${tmpdir} "

cat <<EOF >> ${tmpdir}/csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${service}
DNS.2 = ${service}.${namespace}
DNS.3 = ${service}.${namespace}.svc
EOF

openssl genrsa -out ${tmpdir}/server-key.pem 2048
openssl req -new -key ${tmpdir}/server-key.pem -subj "/CN=${service}.${namespace}.svc" -out ${tmpdir}/server.csr -config ${tmpdir}/csr.conf

# clean-up any previously created CSR for our service. Ignore errors if not present.
kubectl delete csr ${csrName} 2>/dev/null || true

# create  server cert/key CSR and  send to k8s API
cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: ${csrName}
spec:
  groups:
  - system:authenticated
  request: $(cat ${tmpdir}/server.csr | base64 | tr -d '\n')
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

# verify CSR has been created
while true; do
    kubectl get csr ${csrName}
    if [ "$?" -eq 0 ]; then
        break
    fi
done


# approve and fetch the signed certificate
kubectl certificate approve ${csrName}
# verify certificate has been signed
for x in $(seq 10); do
    serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
    if [[ ${serverCert} != '' ]]; then
        break
    fi
    sleep 1
done
if [[ ${serverCert} == '' ]]; then
    echo "ERROR: After approving csr ${csrName}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
    exit 1
fi
echo ${serverCert} | openssl base64 -d -A -out ${tmpdir}/server-cert.pem


# create the secret with CA cert and server cert/key
kubectl create secret generic credhub-webhook-cert \
        --from-file=key.pem=${tmpdir}/server-key.pem \
        --from-file=cert.pem=${tmpdir}/server-cert.pem \
        --dry-run -o yaml |
    kubectl -n ${namespace} apply -f -

# create the webhook 

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

# ensure we delete then recreate all our services

kubectl -n ${namespace} delete -f rbac.yaml
kubectl -n ${namespace} delete -f webhook.yaml
kubectl -n ${namespace} delete -f service.yaml
kubectl -n ${namespace} delete -f deployment.yaml
kubectl -n ${namespace} create -f rbac.yaml
kubectl -n ${namespace} create -f webhook.yaml
kubectl -n ${namespace} create -f service.yaml
kubectl -n ${namespace} create -f deployment.yaml