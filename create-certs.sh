#!/bin/bash

set -e

echo "
Generate certificate suitable for use with an kubernetes-credhub webhook service.

OpenSSL is required
kubectl is required

Ensure kubectl is logged in with a user that has permission to 
approve CSRs.

This script uses k8s' CertificateSigningRequest API to a generate a
certificate signed by k8s CA suitable for use with sidecar-injector webhook
services. This requires permissions to create and approve CSR. See
https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster for
detailed explantion and additional instructions.

The server key/cert k8s CA cert are stored under a generatedCerts folder.



"


namespace=kubernetes-credhub







