package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

func TestAgentDeletesAfterLogDrainWithoutClientClose(t *testing.T) {
	for _, scenario := range []struct {
		name              string
		logs              string
		wantError         string
		wantFinals        int
		complete          bool
		deleteForbidden   bool
		closeConcurrently bool
	}{
		{
			name: "complete",
			logs: `{"schema_version":1,"kind":"status","attachment_id":"source","side":"source","final":true,"complete":true,"sequence":1,"diagnostics":[{"hook":"tcx/ingress","seen":1,"emitted":1}]}
{"schema_version":1,"kind":"status","attachment_id":"backend","side":"backend","final":true,"complete":true}`,
			wantFinals: 2, complete: true,
		},
		{name: "missing-finals", wantError: "without final capture status", wantFinals: 2},
		{name: "malformed-output", logs: "{bad json", wantError: "decode agent", wantFinals: 2},
		{
			name: "incomplete",
			logs: `{"schema_version":1,"kind":"status","attachment_id":"source","side":"source","final":true,"complete":false}
{"schema_version":1,"kind":"status","attachment_id":"backend","side":"backend","final":true,"complete":false}`,
			wantError: "incomplete final capture status", wantFinals: 2,
		},
		{
			name: "cleanup-failure",
			logs: `{"schema_version":1,"kind":"status","attachment_id":"source","side":"source","final":true,"complete":true}
{"schema_version":1,"kind":"status","attachment_id":"backend","side":"backend","final":true,"complete":true}`,
			wantError: "delete agent Pod demo/agent-test failed", wantFinals: 2, complete: true,
			deleteForbidden: true,
		},
		{
			name: "concurrent-client-close",
			logs: `{"schema_version":1,"kind":"status","attachment_id":"source","side":"source","final":true,"complete":true}
{"schema_version":1,"kind":"status","attachment_id":"backend","side":"backend","final":true,"complete":true}`,
			wantFinals: 2, complete: true, closeConcurrently: true,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var deletes atomic.Int32
			logStarted := make(chan struct{})
			finishLogs := make(chan struct{})
			var finishOnce sync.Once
			finish := func() { finishOnce.Do(func() { close(finishLogs) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodDelete:
					deletes.Add(1)
					var options metav1.DeleteOptions
					if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
						t.Error(err)
					}
					if options.Preconditions == nil || options.Preconditions.UID == nil ||
						*options.Preconditions.UID != "agent-uid" {
						t.Error("deletion must identify the created Pod UID")
					}
					if scenario.deleteForbidden {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","message":"denied","code":403}`)
						return
					}
					fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Success"}`)
				case strings.HasSuffix(r.URL.Path, "/log"):
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					close(logStarted)
					select {
					case <-finishLogs:
						fmt.Fprintln(w, scenario.logs)
					case <-r.Context().Done():
					}
				default:
					fmt.Fprint(w, `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"agent-test","namespace":"demo","uid":"agent-uid"},"status":{"phase":"Running"}}`)
				}
			}))
			defer server.Close()
			defer finish()
			clientset, err := kubernetes.NewForConfig(&rest.Config{
				Host:          server.URL,
				ContentConfig: rest.ContentConfig{ContentType: "application/json"},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := (&Client{Clientset: clientset}).StartAgent(ctx, AgentOptions{
				Namespace: "demo", Node: "worker",
				Targets: []AgentTarget{
					{AttachmentID: "source", Side: "source"},
					{AttachmentID: "backend", Side: "backend"},
				},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			<-logStarted
			if deletes.Load() != 0 {
				t.Fatal("Pod deleted before the log stream finished")
			}
			concurrentClose := make(chan error, 1)
			if scenario.closeConcurrently {
				go func() { concurrentClose <- stream.Close() }()
			}
			finish()
			select {
			case <-stream.Done:
			case <-ctx.Done():
				t.Fatal("log completion did not finish cleanup")
			}
			if deletes.Load() != 1 {
				t.Fatalf("deletions before client Close = %d, want 1", deletes.Load())
			}
			finals := 0
			for observation := range stream.Observations {
				if observation.Final {
					finals++
					if observation.Complete != scenario.complete {
						t.Fatalf("final status changed: %+v", observation)
					}
					if scenario.name == "complete" && observation.Side == "source" &&
						(len(observation.Diagnostics) != 1 || observation.Diagnostics[0].Emitted != 1) {
						t.Fatal("final diagnostic counters lost")
					}
				}
			}
			if finals != scenario.wantFinals {
				t.Fatalf("finals = %d, want %d", finals, scenario.wantFinals)
			}
			err = <-stream.Errors
			if scenario.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), scenario.wantError) {
				t.Fatalf("error = %v, want %q", err, scenario.wantError)
			}
			if err := stream.Close(); (err != nil) != scenario.deleteForbidden {
				t.Fatalf("close error = %v", err)
			}
			if scenario.closeConcurrently {
				if err := <-concurrentClose; err != nil {
					t.Fatal(err)
				}
			}
			if deletes.Load() != 1 {
				t.Fatal("client Close repeated the completed deletion")
			}
		})
	}
}

func TestDeleteAgentPodRetriesTransientFailures(t *testing.T) {
	resource := schema.GroupResource{Resource: "pods"}
	for _, scenario := range []struct {
		name      string
		errors    []error
		wantCalls int
		wantError bool
	}{
		{"success", []error{nil}, 1, false},
		{"already-gone", []error{apierrors.NewNotFound(resource, "agent")}, 1, false},
		{"retry", []error{apierrors.NewServiceUnavailable("unavailable"), nil}, 2, false},
		{"retry-already-gone", []error{apierrors.NewTimeoutError("timeout", 0), apierrors.NewNotFound(resource, "agent")}, 2, false},
		{"exhausted", []error{apierrors.NewServiceUnavailable("unavailable")}, 3, true},
		{"forbidden", []error{apierrors.NewForbidden(resource, "agent", errors.New("denied"))}, 1, true},
		{"uid-conflict", []error{apierrors.NewConflict(resource, "agent", errors.New("UID changed"))}, 1, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			clientset := fake.NewClientset()
			calls := 0
			clientset.PrependReactor("delete", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
				err := scenario.errors[min(calls, len(scenario.errors)-1)]
				calls++
				return true, nil, err
			})
			client := &Client{Clientset: clientset}
			err := client.deleteAgentPod(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo", Name: "agent", UID: "uid",
			}})
			if calls != scenario.wantCalls || (err != nil) != scenario.wantError {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			if err != nil && !strings.Contains(err.Error(), "demo/agent") {
				t.Fatalf("remaining Pod not identified: %v", err)
			}
		})
	}
}
