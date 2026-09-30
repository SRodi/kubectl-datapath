package kube

import (
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AgentTarget struct {
	PodUID         string   `json:"pod_uid,omitempty"`
	AttachmentID   string   `json:"attachment_id"`
	Side           string   `json:"side"`
	CaptureConnect bool     `json:"capture_connect,omitempty"`
	RouteTo        string   `json:"route_to,omitempty"`
	FlowAddresses  []string `json:"flow_addresses,omitempty"`
}

type AgentOptions struct {
	Namespace       string
	Image           string
	ImagePullSecret string
	Node            string
	Targets         []AgentTarget
	PodUID          string
	SessionID       string
	AttachmentID    string
	Side            string
	CaptureConnect  bool
	RouteTo         string
	FlowAddresses   []string
}

func AgentPod(options AgentOptions) *corev1.Pod {
	automount := false
	privileged := true
	readOnlyRoot := true
	runAsUser := int64(0)
	deadline := int64((30 * time.Minute).Seconds())
	args := []string{
		"agent",
		"--session-id", options.SessionID,
		"--node", options.Node,
	}
	if len(options.Targets) > 0 {
		for _, target := range options.Targets {
			encoded, err := json.Marshal(target)
			if err != nil {
				panic(err)
			}
			args = append(args, "--target-json", string(encoded))
		}
	} else {
		args = append(args,
			"--attachment-id", options.AttachmentID,
			"--side", options.Side,
		)
		if options.PodUID != "" {
			args = append(args, "--pod-uid", options.PodUID)
		}
		if options.RouteTo != "" {
			args = append(args, "--route-to", options.RouteTo)
			for _, address := range options.FlowAddresses {
				args = append(args, "--flow-address", address)
			}
		}
		if options.CaptureConnect {
			args = append(args, "--capture-connect")
		}
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kubectl-datapath-",
			Namespace:    options.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":         "kubectl-datapath",
				"app.kubernetes.io/component":    "agent",
				"app.kubernetes.io/managed-by":   "kubectl-datapath",
				"datapath.kubernetes.io/session": options.SessionID,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                     options.Node,
			RestartPolicy:                corev1.RestartPolicyNever,
			HostNetwork:                  true,
			HostPID:                      true,
			AutomountServiceAccountToken: &automount,
			ActiveDeadlineSeconds:        &deadline,
			DNSPolicy:                    corev1.DNSClusterFirstWithHostNet,
			Tolerations: []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
			},
			Containers: []corev1.Container{{
				Name:            "agent",
				Image:           options.Image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"/kubectl-datapath"},
				Args:            args,
				SecurityContext: &corev1.SecurityContext{
					Privileged:             &privileged,
					ReadOnlyRootFilesystem: &readOnlyRoot,
					RunAsUser:              &runAsUser,
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "host-proc", MountPath: "/host/proc", ReadOnly: true},
					{Name: "host-cgroup", MountPath: "/host/sys/fs/cgroup", ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				{
					Name: "host-proc",
					VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
						Path: "/proc", Type: hostPathType(corev1.HostPathDirectory),
					}},
				},
				{
					Name: "host-cgroup",
					VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
						Path: "/sys/fs/cgroup", Type: hostPathType(corev1.HostPathDirectory),
					}},
				},
			},
		},
	}
	if options.ImagePullSecret != "" {
		pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: options.ImagePullSecret}}
	}
	return pod
}

func hostPathType(value corev1.HostPathType) *corev1.HostPathType {
	return &value
}
