package kube

import (
	"encoding/json"
	"testing"
)

func TestAgentPodHasUniqueCredentialFreeLifecycle(t *testing.T) {
	pod := AgentPod(AgentOptions{
		Namespace:      "kube-system",
		Image:          "example.invalid/agent@sha256:abc",
		Node:           "worker-a",
		PodUID:         "uid",
		SessionID:      "session",
		CaptureConnect: true,
	})
	if pod.GenerateName == "" || pod.Name != "" {
		t.Fatal("agent Pod must use generateName")
	}

	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("agent Pod must disable ServiceAccount token automount")
	}

	if len(pod.Spec.Containers) != 1 || len(pod.Spec.Containers[0].Command) == 0 {
		t.Fatal("agent must be the container main process")
	}
	args := pod.Spec.Containers[0].Args
	if !contains(args, "--capture-connect") {
		t.Fatal("source trace agent must enable connect capture")
	}
	if len(pod.Spec.Volumes) != 2 || len(pod.Spec.Containers[0].VolumeMounts) != 2 {
		t.Fatal("agent must mount host procfs and cgroup v2 read-only")
	}
}

func TestAgentPodConfiguresRouteSelectedTransitCapture(t *testing.T) {
	pod := AgentPod(AgentOptions{
		Namespace: "kube-system", Image: "agent:dev", Node: "worker-a",
		SessionID: "session", AttachmentID: "transit-source-worker-b", Side: "transit-source",
		RouteTo: "192.0.2.20", FlowAddresses: []string{"10.244.0.5", "10.244.1.8"},
	})
	args := pod.Spec.Containers[0].Args
	for _, expected := range []string{
		"--route-to", "192.0.2.20",
		"--flow-address", "10.244.0.5",
		"--flow-address", "10.244.1.8",
	} {
		if !contains(args, expected) {
			t.Fatalf("%q missing from agent args: %#v", expected, args)
		}
	}
	if contains(args, "--pod-uid") {
		t.Fatalf("transit agent must not resolve a Pod veth: %#v", args)
	}
}

func TestAgentPodConfiguresMultipleNodeTargets(t *testing.T) {
	targets := []AgentTarget{
		{
			PodUID: "source-uid", AttachmentID: "source", Side: "source",
			CaptureConnect: true,
		},
		{
			AttachmentID: "transit-source-worker-b", Side: "transit-source",
			RouteTo: "192.0.2.20", FlowAddresses: []string{"10.244.0.5", "10.244.1.8"},
		},
	}
	pod := AgentPod(AgentOptions{
		Namespace: "kube-system", Image: "agent:dev", Node: "worker-a",
		SessionID: "session", Targets: targets,
	})
	args := pod.Spec.Containers[0].Args
	var encoded []string
	for index, value := range args {
		if value == "--target-json" && index+1 < len(args) {
			encoded = append(encoded, args[index+1])
		}
	}
	if len(encoded) != len(targets) {
		t.Fatalf("target args = %#v", args)
	}
	for index, value := range encoded {
		var decoded AgentTarget
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.AttachmentID != targets[index].AttachmentID {
			t.Fatalf("target %d = %#v", index, decoded)
		}
	}
	if contains(args, "--pod-uid") || contains(args, "--route-to") {
		t.Fatalf("multi-target configuration must use only target JSON: %#v", args)
	}
}

func TestAgentPodConfiguresImagePullSecret(t *testing.T) {
	pod := AgentPod(AgentOptions{
		Namespace: "kube-system", Image: "ghcr.io/example/private:sha",
		Node: "worker-a", SessionID: "session", ImagePullSecret: "ghcr-pull",
		Targets: []AgentTarget{{
			PodUID: "source-uid", AttachmentID: "source", Side: "source",
		}},
	})
	if len(pod.Spec.ImagePullSecrets) != 1 || pod.Spec.ImagePullSecrets[0].Name != "ghcr-pull" {
		t.Fatalf("imagePullSecrets = %#v", pod.Spec.ImagePullSecrets)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
