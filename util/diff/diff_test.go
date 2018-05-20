package diff

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/argoproj/argo-cd/test"
	"github.com/argoproj/argo-cd/util/kube"
	"github.com/stretchr/testify/assert"
	"github.com/yudai/gojsondiff/formatter"
	"golang.org/x/crypto/ssh/terminal"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	formatOpts = formatter.AsciiFormatterConfig{
		Coloring: terminal.IsTerminal(int(os.Stdout.Fd())),
	}
)

func TestDiff(t *testing.T) {
	leftDep := test.DemoDeployment()
	leftUn := kube.MustToUnstructured(leftDep)

	diffRes := Diff(leftUn, leftUn)
	assert.False(t, diffRes.Diff.Modified())
	ascii, err := diffRes.ASCIIFormat(leftUn, formatOpts)
	assert.Nil(t, err)
	if ascii != "" {
		log.Println(ascii)
	}
}

func TestDiffWithNils(t *testing.T) {
	dep := test.DemoDeployment()
	resource := kube.MustToUnstructured(dep)

	diffRes := Diff(nil, resource)
	// NOTE: if live is non-nil, and config is nil, this is not considered difference
	// This "difference" is checked at the comparator.
	assert.False(t, diffRes.Diff.Modified())

	diffRes = Diff(resource, nil)
	assert.True(t, diffRes.Diff.Modified())
}

func TestDiffArraySame(t *testing.T) {
	leftDep := test.DemoDeployment()
	rightDep := leftDep.DeepCopy()

	leftUn := kube.MustToUnstructured(leftDep)
	rightUn := kube.MustToUnstructured(rightDep)

	left := []*unstructured.Unstructured{leftUn}
	right := []*unstructured.Unstructured{rightUn}
	diffResList, err := DiffArray(left, right)
	assert.Nil(t, err)
	assert.False(t, diffResList.Modified)
}

func TestDiffArrayAdditions(t *testing.T) {
	leftDep := test.DemoDeployment()
	rightDep := leftDep.DeepCopy()
	rightDep.Status.Replicas = 1

	leftUn := kube.MustToUnstructured(leftDep)
	rightUn := kube.MustToUnstructured(rightDep)

	left := []*unstructured.Unstructured{leftUn}
	right := []*unstructured.Unstructured{rightUn}
	diffResList, err := DiffArray(left, right)
	assert.Nil(t, err)
	assert.False(t, diffResList.Modified)
}

func TestDiffArrayModification(t *testing.T) {
	leftDep := test.DemoDeployment()
	rightDep := leftDep.DeepCopy()
	ten := int32(10)
	rightDep.Spec.Replicas = &ten

	leftUn := kube.MustToUnstructured(leftDep)
	rightUn := kube.MustToUnstructured(rightDep)

	left := []*unstructured.Unstructured{leftUn}
	right := []*unstructured.Unstructured{rightUn}
	diffResList, err := DiffArray(left, right)
	assert.Nil(t, err)
	assert.True(t, diffResList.Modified)
}

// TestThreeWayDiff will perform a diff when there is a kubectl.kubernetes.io/last-applied-configuration
// present in the live object.
func TestThreeWayDiff(t *testing.T) {
	// 1. get config and live to be the same. Both have a foo annotation.
	configDep := test.DemoDeployment()
	configDep.ObjectMeta.Namespace = ""
	configDep.Annotations = map[string]string{
		"foo": "bar",
	}
	liveDep := configDep.DeepCopy()

	// 2. add a extra field to the live. this simulates kubernetes adding default values in the
	// object. We should not consider defaulted values as a difference
	liveDep.SetNamespace("default")
	configUn := kube.MustToUnstructured(configDep)
	liveUn := kube.MustToUnstructured(liveDep)
	res := Diff(configUn, liveUn)
	if !assert.False(t, res.Modified) {
		ascii, err := res.ASCIIFormat(configUn, formatOpts)
		assert.Nil(t, err)
		log.Println(ascii)
	}

	// 3. Add a last-applied-configuration annotation in the live. There should still not be any
	// difference
	configBytes, err := json.Marshal(configDep)
	assert.Nil(t, err)
	liveDep.Annotations[v1.LastAppliedConfigAnnotation] = string(configBytes)
	configUn = kube.MustToUnstructured(configDep)
	liveUn = kube.MustToUnstructured(liveDep)
	res = Diff(configUn, liveUn)
	if !assert.False(t, res.Modified) {
		ascii, err := res.ASCIIFormat(configUn, formatOpts)
		assert.Nil(t, err)
		log.Println(ascii)
	}

	// 4. Remove the foo annotation from config and perform the diff again. We should detect a
	// difference since three-way diff detects the removal of a managed field
	delete(configDep.Annotations, "foo")
	configUn = kube.MustToUnstructured(configDep)
	liveUn = kube.MustToUnstructured(liveDep)
	res = Diff(configUn, liveUn)
	assert.True(t, res.Modified)

	// 5. Just to prove three way diff incorporates last-applied-configuration, remove the
	// last-applied-configuration annotation from the live object, and redo the diff. This time,
	// the diff will report not modified (because we have no way of knowing what was a defaulted
	// field without this annotation)
	delete(liveDep.Annotations, v1.LastAppliedConfigAnnotation)
	configUn = kube.MustToUnstructured(configDep)
	liveUn = kube.MustToUnstructured(liveDep)
	res = Diff(configUn, liveUn)
	ascii, err := res.ASCIIFormat(configUn, formatOpts)
	assert.Nil(t, err)
	if ascii != "" {
		log.Println(ascii)
	}
	assert.False(t, res.Modified)
}

var demoConfig = `
{
  "apiVersion": "v1",
  "kind": "ServiceAccount",
  "metadata": {
    "labels": {
      "applications.argoproj.io/app-name": "argocd-demo"
    },
    "name": "application-controller"
  }
}
`

var demoLive = `
{
  "apiVersion": "v1",
  "kind": "ServiceAccount",
  "metadata": {
    "annotations": {
      "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"ServiceAccount\",\"metadata\":{\"annotations\":{},\"labels\":{\"applications.argoproj.io/app-name\":\"argocd-demo\"},\"name\":\"application-controller\",\"namespace\":\"argocd-demo\"}}\n"
    },
    "creationTimestamp": "2018-04-16T22:08:57Z",
    "labels": {
      "applications.argoproj.io/app-name": "argocd-demo"
    },
    "name": "application-controller",
    "namespace": "argocd-demo",
    "resourceVersion": "7584502",
    "selfLink": "/api/v1/namespaces/argocd-demo/serviceaccounts/application-controller",
    "uid": "c22bb2b4-41c2-11e8-978a-028445d52ec8"
  },
  "secrets": [
    {
      "name": "application-controller-token-kfxct"
    }
  ]
}
`

// Tests a real world example
func TestDiffActualExample(t *testing.T) {
	var configUn, liveUn unstructured.Unstructured
	err := json.Unmarshal([]byte(demoConfig), &configUn.Object)
	assert.Nil(t, err)
	err = json.Unmarshal([]byte(demoLive), &liveUn.Object)
	assert.Nil(t, err)
	dr := Diff(&configUn, &liveUn)
	assert.False(t, dr.Modified)
	ascii, err := dr.ASCIIFormat(&configUn, formatOpts)
	assert.Nil(t, err)
	if ascii != "" {
		log.Println(ascii)
	}

}

func TestDiffActualExample2(t *testing.T) {
	configObjStr := `
{
  "apiVersion": "apps/v1beta2",
  "kind": "Deployment",
  "metadata": {
    "labels": {
      "applications.argoproj.io/app-name": "jesse-test"
    },
    "name": "application-controller"
  },
  "spec": {
    "selector": {
      "matchLabels": {
        "app": "application-controller"
      }
    },
    "template": {
      "metadata": {
        "labels": {
          "app": "application-controller",
          "applications.argoproj.io/app-name": "jesse-test"
        }
      },
      "spec": {
        "containers": [
          {
            "command": [
              "/argocd-application-controller",
              "--repo-server",
              "argocd-repo-server:8081"
            ],
            "image": "argoproj/argocd-application-controller:v0.4.0",
            "imagePullPolicy": "Always",
            "name": "application-controller"
          }
        ],
        "serviceAccountName": "application-controller"
      }
    }
  }
}`
	liveObjStr := `
{
  "apiVersion": "apps/v1beta2",
  "kind": "Deployment",
  "metadata": {
    "annotations": {
      "deployment.kubernetes.io/revision": "5",
      "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"apps/v1beta2\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{},\"labels\":{\"applications.argoproj.io/app-name\":\"jesse-test\"},\"name\":\"application-controller\",\"namespace\":\"jesse-test\"},\"spec\":{\"selector\":{\"matchLabels\":{\"app\":\"application-controller\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"application-controller\",\"applications.argoproj.io/app-name\":\"jesse-test\"}},\"spec\":{\"containers\":[{\"command\":[\"/argocd-application-controller\",\"--repo-server\",\"argocd-repo-server:8081\"],\"image\":\"argoproj/argocd-application-controller:v0.4.0\",\"name\":\"application-controller\"}],\"serviceAccountName\":\"application-controller\"}}}}\n"
    },
    "creationTimestamp": "2018-05-01T00:10:46Z",
    "generation": 12,
    "labels": {
      "app": "application-controller",
      "applications.argoproj.io/app-name": "jesse-test"
    },
    "name": "application-controller",
    "namespace": "jesse-test",
    "resourceVersion": "11098215",
    "selfLink": "/apis/apps/v1beta2/namespaces/jesse-test/deployments/application-controller",
    "uid": "189330dc-4cd4-11e8-a6c3-06c0e6e3f55c"
  },
  "spec": {
    "progressDeadlineSeconds": 600,
    "replicas": 0,
    "revisionHistoryLimit": 10,
    "selector": {
      "matchLabels": {
        "app": "application-controller"
      }
    },
    "strategy": {
      "rollingUpdate": {
        "maxSurge": "25%",
        "maxUnavailable": "25%"
      },
      "type": "RollingUpdate"
    },
    "template": {
      "metadata": {
        "creationTimestamp": null,
        "labels": {
          "app": "application-controller",
          "applications.argoproj.io/app-name": "jesse-test"
        }
      },
      "spec": {
        "containers": [
          {
            "command": [
              "/argocd-application-controller",
              "--repo-server",
              "argocd-repo-server:8081"
            ],
            "image": "argoproj/argocd-application-controller:v0.4.0",
            "imagePullPolicy": "Always",
            "name": "application-controller",
            "resources": {},
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File"
          }
        ],
        "dnsPolicy": "ClusterFirst",
        "restartPolicy": "Always",
        "schedulerName": "default-scheduler",
        "securityContext": {},
        "serviceAccount": "application-controller",
        "serviceAccountName": "application-controller",
        "terminationGracePeriodSeconds": 30
      }
    }
  },
  "status": {
    "conditions": [
      {
        "lastTransitionTime": "2018-05-15T07:47:08Z",
        "lastUpdateTime": "2018-05-15T07:47:08Z",
        "message": "Deployment has minimum availability.",
        "reason": "MinimumReplicasAvailable",
        "status": "True",
        "type": "Available"
      },
      {
        "lastTransitionTime": "2018-05-01T00:10:46Z",
        "lastUpdateTime": "2018-05-17T08:47:56Z",
        "message": "ReplicaSet \"application-controller-648ff67448\" has successfully progressed.",
        "reason": "NewReplicaSetAvailable",
        "status": "True",
        "type": "Progressing"
      }
    ],
    "observedGeneration": 12
  }
}`
	var configUn, liveUn unstructured.Unstructured
	err := json.Unmarshal([]byte(configObjStr), &configUn.Object)
	assert.Nil(t, err)
	err = json.Unmarshal([]byte(liveObjStr), &liveUn.Object)
	assert.Nil(t, err)
	dr := Diff(&configUn, &liveUn)
	assert.False(t, dr.Diff.Modified())
	assert.False(t, dr.Modified)
	ascii, err := dr.ASCIIFormat(&configUn, formatOpts)
	assert.Nil(t, err)
	if ascii != "" {
		log.Println(ascii)
	}

}
