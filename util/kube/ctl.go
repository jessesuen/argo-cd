package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/kubectl/scheme"

	"github.com/argoproj/argo-cd/util"
)

type Kubectl interface {
	ApplyResource(config *rest.Config, obj *unstructured.Unstructured, namespace string, dryRun, force bool) (string, error)
	ConvertToVersion(obj *unstructured.Unstructured, group, version string) (*unstructured.Unstructured, error)
	DeleteResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string, forceDelete bool) error
	GetResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string) (*unstructured.Unstructured, error)
	WatchResources(ctx context.Context, config *rest.Config, namespace string) (chan watch.Event, error)
	GetResources(config *rest.Config, namespace string) ([]*unstructured.Unstructured, error)
	GetAPIResources(config *rest.Config) ([]*metav1.APIResourceList, error)
}

type KubectlCmd struct{}

func (k KubectlCmd) GetAPIResources(config *rest.Config) ([]*metav1.APIResourceList, error) {
	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	return disco.ServerResources()
}

// GetResources returns all kubernetes resources
func (k KubectlCmd) GetResources(config *rest.Config, namespace string) ([]*unstructured.Unstructured, error) {

	listSupported := func(groupVersion string, apiResource *metav1.APIResource) bool {
		return isSupportedVerb(apiResource, listVerb) && !isExcludedResourceGroup(*apiResource)
	}
	apiResIfs, err := filterAPIResources(config, listSupported, namespace)
	if err != nil {
		return nil, err
	}

	var asyncErr error
	var result []*unstructured.Unstructured
	var wg sync.WaitGroup
	var lock sync.Mutex
	wg.Add(len(apiResIfs))
	for _, apiResIf := range apiResIfs {
		go func(resourceIf dynamic.ResourceInterface) {
			defer wg.Done()
			list, err := resourceIf.List(metav1.ListOptions{})
			if err != nil {
				if !apierr.IsNotFound(err) {
					asyncErr = err
				}
				return
			}
			for i := range list.Items {
				item := list.Items[i]
				lock.Lock()
				result = append(result, &item)
				lock.Unlock()
			}
		}(apiResIf.resourceIf)
	}
	wg.Wait()
	return result, asyncErr
}

const watchResourcesRetryTimeout = 1 * time.Second

// WatchResources Watches all the existing resources with the provided label name in the provided namespace in the cluster provided by the config
func (k KubectlCmd) WatchResources(
	ctx context.Context,
	config *rest.Config,
	namespace string,
) (chan watch.Event, error) {
	watchSupported := func(groupVersion string, apiResource *metav1.APIResource) bool {
		return isSupportedVerb(apiResource, watchVerb) && !isExcludedResourceGroup(*apiResource)
	}
	log.Infof("Start watching for resources changes with in cluster %s", config.Host)
	apiResIfs, err := filterAPIResources(config, watchSupported, namespace)
	if err != nil {
		return nil, err
	}
	ch := make(chan watch.Event)
	go func() {
		var wg sync.WaitGroup
		wg.Add(len(apiResIfs))
		for _, a := range apiResIfs {
			go func(apiResIf apiResourceInterface) {
				defer wg.Done()

				util.RetryUntilSucceed(func() (err error) {
					defer func() {
						if r := recover(); r != nil {
							message := fmt.Sprintf("Recovered from panic: %+v\n%s", r, debug.Stack())
							log.Error(message)
							err = errors.New(message)
						}
					}()
					watchCh := WatchWithRetry(ctx, func() (i watch.Interface, e error) {
						return apiResIf.resourceIf.Watch(metav1.ListOptions{})
					})
					for next := range watchCh {
						if next.Error != nil {
							return next.Error
						}
						ch <- watch.Event{
							Object: next.Object,
							Type:   next.Type,
						}
					}
					return nil
				}, fmt.Sprintf("watch resources %s %s/%s", config.Host, apiResIf.groupVersion, apiResIf.apiResource.Kind), ctx, watchResourcesRetryTimeout)
			}(a)
		}
		wg.Wait()
		close(ch)
		log.Infof("Stop watching for resources changes with in cluster %s", config.Host)
	}()
	return ch, nil
}

// GetResource returns resource
func (k KubectlCmd) GetResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string) (*unstructured.Unstructured, error) {
	dynamicIf, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}
	apiResource, err := ServerResourceForGroupVersionKind(disco, gvk)
	if err != nil {
		return nil, err
	}
	resource := gvk.GroupVersion().WithResource(apiResource.Name)
	resourceIf := ToResourceInterface(dynamicIf, apiResource, resource, namespace)
	return resourceIf.Get(name, metav1.GetOptions{})
}

// DeleteResource deletes resource
func (k KubectlCmd) DeleteResource(config *rest.Config, gvk schema.GroupVersionKind, name string, namespace string, forceDelete bool) error {
	dynamicIf, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}
	disco, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}
	apiResource, err := ServerResourceForGroupVersionKind(disco, gvk)
	if err != nil {
		return err
	}
	resource := gvk.GroupVersion().WithResource(apiResource.Name)
	resourceIf := ToResourceInterface(dynamicIf, apiResource, resource, namespace)
	propagationPolicy := metav1.DeletePropagationForeground
	deleteOptions := &metav1.DeleteOptions{PropagationPolicy: &propagationPolicy}
	if forceDelete {
		zeroGracePeriod := int64(0)
		deleteOptions.GracePeriodSeconds = &zeroGracePeriod
	}

	return resourceIf.Delete(name, deleteOptions)
}

// ApplyResource performs an apply of a unstructured resource
func (k KubectlCmd) ApplyResource(config *rest.Config, obj *unstructured.Unstructured, namespace string, dryRun, force bool) (string, error) {
	log.Infof("Applying resource %s/%s in cluster: %s, namespace: %s", obj.GetKind(), obj.GetName(), config.Host, namespace)
	f, err := ioutil.TempFile(util.TempDir, "")
	if err != nil {
		return "", fmt.Errorf("Failed to generate temp file for kubeconfig: %v", err)
	}
	_ = f.Close()
	err = WriteKubeConfig(config, namespace, f.Name())
	if err != nil {
		return "", fmt.Errorf("Failed to write kubeconfig: %v", err)
	}
	defer util.DeleteFile(f.Name())
	manifestBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	var out []string
	// If it is an RBAC resource, run `kubectl auth reconcile`. This is preferred over
	// `kubectl apply`, which cannot tolerate changes in roleRef, which is an immutable field.
	// See: https://github.com/kubernetes/kubernetes/issues/66353
	// `auth reconcile` will delete and recreate the resource if necessary
	if obj.GetAPIVersion() == "rbac.authorization.k8s.io/v1" {
		// `kubectl auth reconcile` has a side effect of auto-creating namespaces if it doesn't exist.
		// See: https://github.com/kubernetes/kubernetes/issues/71185. This is behavior which we do
		// not want. We need to check if the namespace exists, before know if it is safe to run this
		// command. Skip this for dryRuns.
		if !dryRun && namespace != "" {
			kubeClient, err := kubernetes.NewForConfig(config)
			if err != nil {
				return "", err
			}
			_, err = kubeClient.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
		}
		outReconcile, err := runKubectl(f.Name(), namespace, []string{"auth", "reconcile"}, manifestBytes, dryRun)
		if err != nil {
			return "", err
		}
		out = append(out, outReconcile)
		// We still want to fallthrough and run `kubectl apply` in order set the
		// last-applied-configuration annotation in the object.
	}

	// Run kubectl apply
	applyArgs := []string{"apply"}
	if force {
		applyArgs = append(applyArgs, "--force")
	}
	outApply, err := runKubectl(f.Name(), namespace, applyArgs, manifestBytes, dryRun)
	if err != nil {
		return "", err
	}
	out = append(out, outApply)
	return strings.Join(out, ". "), nil
}

func runKubectl(kubeconfigPath string, namespace string, args []string, manifestBytes []byte, dryRun bool) (string, error) {
	cmdArgs := append([]string{"--kubeconfig", kubeconfigPath, "-f", "-"}, args...)
	if namespace != "" {
		cmdArgs = append(cmdArgs, "-n", namespace)
	}
	if dryRun {
		cmdArgs = append(cmdArgs, "--dry-run")
	}
	cmd := exec.Command("kubectl", cmdArgs...)
	log.Info(cmd.Args)
	log.Debug(string(manifestBytes))
	cmd.Stdin = bytes.NewReader(manifestBytes)
	out, err := cmd.Output()
	if err != nil {
		if exErr, ok := err.(*exec.ExitError); ok {
			errMsg := cleanKubectlOutput(string(exErr.Stderr))
			return "", errors.New(errMsg)
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ConvertToVersion converts an unstructured object into the specified group/version
func (k KubectlCmd) ConvertToVersion(obj *unstructured.Unstructured, group, version string) (*unstructured.Unstructured, error) {
	return k.ConvertToVersionOrig(obj, group, version)
	gvk := obj.GroupVersionKind()
	if gvk.Group == group && gvk.Version == version {
		return obj.DeepCopy(), nil
	}
	// targetGVK := schema.GroupVersionKind{
	// 	Group:   group,
	// 	Version: version,
	// 	Kind:    obj.GetKind(),
	// }
	internalEncoder := scheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)
	encoder := unstructured.JSONFallbackEncoder{Encoder: internalEncoder}

	versionedObj, err := scheme.Scheme.New(obj.GroupVersionKind())
	if err != nil {
		return nil, err
	}
	log.Info(obj.GroupVersionKind())
	log.Info(versionedObj.GetObjectKind())

	targetVersions := []schema.GroupVersion{}
	var converted runtime.Object

	// objects that are not part of api.Scheme must be converted to JSON
	// TODO: convert to map[string]interface{}, attach to runtime.Unknown?
	if _, _, err := scheme.Scheme.ObjectKinds(obj); runtime.IsNotRegisteredError(err) {
		log.Infof("is not registered: %s", obj.GroupVersionKind())
		// TODO: ideally this would encode to version, but we don't expose multiple codecs here.
		data, err := runtime.Encode(encoder, obj)
		if err != nil {
			return nil, err
		}
		// TODO: Set ContentEncoding and ContentType.
		converted = &runtime.Unknown{Raw: data}
	} else {
		log.Infof("registered: %s", obj.GroupVersionKind())
		targetVersions = append(targetVersions, schema.GroupVersion{Group: group, Version: version})
		converted, err = tryConvert(scheme.Scheme, obj, targetVersions...)
		if err != nil {
			return nil, err
		}
	}

	// Jesse
	convertedObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(converted)
	if err != nil {
		return nil, err
	}
	newObj := unstructured.Unstructured{Object: convertedObj}
	return &newObj, nil

	// converted, err := scheme.Scheme.ConvertToVersion(versionedObj, schema.GroupVersion{Group: group, Version: version})
	// if converted == nil {
	// 	bytes, _ := json.Marshal(obj)
	// 	log.Info(string(bytes))
	// 	//obj.GroupVersionKind
	// 	return nil, fmt.Errorf("failed to convert %s, %s to %s/%s: %v", obj.GroupVersionKind(), obj.GetName(), group, version, err)
	// }
	// convertedObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(converted)
	// if err != nil {
	// 	return nil, err
	// }
	// newObj := unstructured.Unstructured{Object: convertedObj}
	// // ToUnstructured does not populate type metadata. Need to set it manually
	// //newObj.SetGroupVersionKind(targetGVK)
	// //newObj.SetNamespace(obj.GetNamespace())
	// return &newObj, nil
}

// ConvertToVersion converts an unstructured object into the specified group/version
func (k KubectlCmd) ConvertToVersionOrig(obj *unstructured.Unstructured, group, version string) (*unstructured.Unstructured, error) {
	gvk := obj.GroupVersionKind()
	if gvk.Group == group && gvk.Version == version {
		return obj.DeepCopy(), nil
	}
	targetVersion := schema.GroupVersion{Group: group, Version: version}
	item, err := scheme.Scheme.New(obj.GroupVersionKind())
	if err != nil {
		return nil, err
	}
	//unmarshalledObj := reflect.New(reflect.TypeOf(item).Elem()).Interface().(runtime.Object)
	//versionedObj := reflect.New(reflect.TypeOf(item).Elem()).Interface()
	//converter := runtime.ObjectConvertor(scheme.Scheme)
	//converter := runtime.ObjectConvertor(legacyscheme.Scheme)
	//converted, err := converter.ConvertToVersion(versionedObj, schema.GroupVersion{Group: group, Version: version})
	//converted, err := converter.ConvertToVersion(versionedObj, runtime.APIVersionInternal)
	converted, err := scheme.Scheme.ConvertToVersion(item, targetVersion)
	if converted == nil {
		bytes, _ := json.Marshal(obj)
		log.Info(string(bytes))
		return nil, fmt.Errorf("failed to convert %s, %s to %s/%s: %v", obj.GroupVersionKind(), obj.GetName(), group, version, err)
	}
	convertedObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(converted)
	if err != nil {
		return nil, err
	}
	newObj := unstructured.Unstructured{Object: convertedObj}
	// ToUnstructured does not populate type metadata. Need to set it manually
	//newObj.SetGroupVersionKind(targetGVK)
	//newObj.SetNamespace(obj.GetNamespace())
	return &newObj, nil
}

// tryConvert attempts to convert the given object to the provided versions in order. This function assumes
// the object is in internal version.
func tryConvert(converter runtime.ObjectConvertor, object runtime.Object, versions ...schema.GroupVersion) (runtime.Object, error) {
	var last error
	for _, version := range versions {
		if version.Empty() {
			return object, nil
		}
		obj, err := converter.ConvertToVersion(object, version)
		if err != nil {
			last = err
			continue
		}
		return obj, nil
	}
	return nil, last
}
