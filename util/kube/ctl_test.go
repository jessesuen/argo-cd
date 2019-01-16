package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/argoproj/argo-cd/test"
)

func TestConvertToVersion(t *testing.T) {
	kubectl := KubectlCmd{}
	obj := test.UnmarshalYAMLFile("testdata/nginx.yaml")

	// convert an extensions/v1beta1 Deployment into an apps/v1
	newObj, err := kubectl.ConvertToVersion(obj, "apps", "v1")
	assert.Nil(t, err)
	gvk := newObj.GroupVersionKind()
	assert.Equal(t, "apps", gvk.Group)
	assert.Equal(t, "v1", gvk.Version)
	val, exists, err := unstructured.NestedString(newObj.Object, "spec", "selector", "matchLabels", "app")
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.True(t, exists)
	assert.Equal(t, "nginx", val)

	// converting it again should not have any affect
	newObj, err = kubectl.ConvertToVersion(obj, "apps", "v1")
	assert.Nil(t, err)
	gvk = newObj.GroupVersionKind()
	assert.Equal(t, "apps", gvk.Group)
	assert.Equal(t, "v1", gvk.Version)

	// ensure error is returned when trying to perform invalid conversion
	_, err = kubectl.ConvertToVersion(obj, "apps", "v2")
	assert.Error(t, err)
}

func TestConvertToVersionNetworkPolicy(t *testing.T) {
	kubectl := KubectlCmd{}
	// convert an extensions/v1beta1 NetworkPolicy into networking.k8s.io/v1
	old := test.UnmarshalYAMLFile("testdata/netpol-extensions-v1beta1.yaml")
	newObj, err := kubectl.ConvertToVersion(old, "networking.k8s.io", "v1")
	assert.Nil(t, err)
	gvk := newObj.GroupVersionKind()
	assert.Equal(t, "networking.k8s.io", gvk.Group)
	assert.Equal(t, "v1", gvk.Version)
	val, exists, err := unstructured.NestedSlice(newObj.Object, "spec", "policyTypes")
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.True(t, exists)
	assert.Equal(t, "Egress", val[0].(string))
	// and networking.k8s.io/v1 into extensions/v1beta1
	new := test.UnmarshalYAMLFile("testdata/netpol-networking.k8s.io-v1.yaml")
	oldObj, err := kubectl.ConvertToVersion(new, "extensions", "v1beta1")
	assert.Nil(t, err)
	gvk = oldObj.GroupVersionKind()
	assert.Equal(t, "extensions", gvk.Group)
	assert.Equal(t, "v1beta1", gvk.Version)
	val, exists, err = unstructured.NestedSlice(oldObj.Object, "spec", "policyTypes")
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.True(t, exists)
	assert.Equal(t, "Egress", val[0].(string))

}

func TestConvertToVersionMatrix(t *testing.T) {
	kubectl := KubectlCmd{}
	obj := test.UnmarshalJSONFile("testdata/deploy-apps-v1.json")

	type groupVersion struct {
		group   string
		version string
	}
	matrix := []groupVersion{
		{"extensions", "v1beta1"},
		{"apps", "v1beta1"},
		{"apps", "v1beta2"},
		{"apps", "v1"},
	}
	for _, gv := range matrix {
		newObj, err := kubectl.ConvertToVersion(obj, gv.group, gv.version)
		assert.Nil(t, err)
		gvk := newObj.GroupVersionKind()
		assert.Equal(t, gv.group, gvk.Group)
		assert.Equal(t, gv.version, gvk.Version)
		val, exists, err := unstructured.NestedString(newObj.Object, "spec", "selector", "matchLabels", "app")
		assert.NoError(t, err)
		assert.True(t, exists)
		assert.True(t, exists)
		assert.Equal(t, "nginx", val)
		// convert it again
		for _, gv := range matrix {
			newObj, err := kubectl.ConvertToVersion(obj, gv.group, gv.version)
			assert.Nil(t, err)
			gvk := newObj.GroupVersionKind()
			assert.Equal(t, gv.group, gvk.Group)
			assert.Equal(t, gv.version, gvk.Version)
			val, exists, err := unstructured.NestedString(newObj.Object, "spec", "selector", "matchLabels", "app")
			assert.NoError(t, err)
			assert.True(t, exists)
			assert.True(t, exists)
			assert.Equal(t, "nginx", val)
		}
	}
}
