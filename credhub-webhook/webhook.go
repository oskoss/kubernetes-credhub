package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
	defaulter     = runtime.ObjectDefaulter(runtimeScheme)
)

var ignoredNamespaces = []string{}

const (
	admissionWebhookAnnotationStatusKey = "credhub.pivotal.io"
	injected                            = "injected"
	volumeName                          = "credhub-volume"
	volumeMountPath                     = "/credhub"
)

type WebhookServer struct {
	server *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type Config struct {
	Containers []corev1.Container `yaml:"containers"`
	Volumes    []corev1.Volume    `yaml:"volumes"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {

	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for it' in special namespace:%v", metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := strings.ToLower(annotations[admissionWebhookAnnotationStatusKey])
	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if status == "" {
		required = false
		glog.Infof("Annotation is not present. Mutation is not required.")
	} else {
		switch status {
		default:
			glog.Infof("Annotation is not yes, y, true, enable, or on. Mutation not required.")
			required = false
		case injected:
			glog.Infof("Mutation already occurred. Mutation is not required.")
			required = false
		case "y", "yes", "true", "on", "enable":
			glog.Infof("Annotation is present. Mutation is required.")
			required = true
		}
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
	return required
}

func addContainer(pod *corev1.Pod) patchOperation {
	first := len(pod.Spec.InitContainers) == 0
	var value interface{}
	container := corev1.Container{
		Image: "oskoss/kubernetes-credhub-init:v0",
		Ports: []corev1.ContainerPort{
			corev1.ContainerPort{
				ContainerPort: 8080,
			},
		},
		Name:            "kubernetes-credhub-init",
		ImagePullPolicy: "Always",
		VolumeMounts: []corev1.VolumeMount{
			corev1.VolumeMount{
				Name:      volumeName,
				MountPath: volumeMountPath,
			},
		},
	}
	value = container
	path := "/spec/initContainers"
	if first {
		value = []corev1.Container{container}
	} else {
		path = path + "/-"
	}
	patch := patchOperation{
		Op:    "add",
		Path:  path,
		Value: value,
	}
	return patch
}

func addVolume(pod *corev1.Pod) patchOperation {

	first := len(pod.Spec.Volumes) == 0
	var value interface{}
	volume := corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	value = volume
	path := "/spec/volumes"
	if first {
		value = []corev1.Volume{volume}
	} else {
		path = path + "/-"
	}
	patch := patchOperation{
		Op:    "add",
		Path:  path,
		Value: value,
	}
	return patch
}

func addVolumeMount(pod *corev1.Pod) patchOperation {
	first := len(pod.Spec.Containers[0].VolumeMounts) == 0

	//TODO Currently we only attach secrets to the first container...probably should do this for all containers.
	var value interface{}
	mount := corev1.VolumeMount{
		Name:      volumeName,
		MountPath: volumeMountPath,
	}
	value = mount
	path := "/spec/containers/0/volumeMounts"
	if first {
		value = []corev1.VolumeMount{mount}
	} else {
		path = path + "/-"
	}

	patch := patchOperation{
		Op:    "add",
		Path:  path,
		Value: value,
	}
	return patch
}

func updateAnnotation() patchOperation {
	patch := patchOperation{
		Op:    "replace",
		Path:  "/metadata/annotations/" + admissionWebhookAnnotationStatusKey,
		Value: injected,
	}
	return patch
}

// create mutation patch for resources
func createPatch(pod *corev1.Pod, annotations map[string]string) ([]byte, error) {

	var patch []patchOperation
	volumePatch := addVolume(pod)
	mountPatch := addVolumeMount(pod)
	initContainersPatch := addContainer(pod)
	annotationPatch := updateAnnotation()
	patch = append(patch, volumePatch)
	patch = append(patch, mountPatch)
	patch = append(patch, initContainersPatch)
	patch = append(patch, annotationPatch)
	return json.Marshal(patch)

}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, annotations)
	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Response written...")
}
