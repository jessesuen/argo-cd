package listers

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	argoappv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	applisters "github.com/argoproj/argo-cd/pkg/client/listers/application/v1alpha1"
)

// NewApplicationLister returns a ApplicationLister but does so using an Unstructured informer and
// converting objects to Applications. Ignores objects that failed to convert.
func NewApplicationLister(informer cache.SharedIndexInformer) applisters.ApplicationLister {
	return &appLister{
		informer: informer,
	}
}

type appLister struct {
	informer cache.SharedIndexInformer
}

// List lists all Applications in the indexer.
func (s *appLister) List(selector labels.Selector) ([]*argoappv1.Application, error) {
	var apps []*argoappv1.Application
	err := cache.ListAll(s.informer.GetIndexer(), selector, func(m interface{}) {
		app, err := FromUnstructured(m.(*unstructured.Unstructured))
		if err != nil {
			log.Warnf("Failed to unmarshal app %v object: %v", m, err)
		} else {
			apps = append(apps, app)
		}
	})
	return apps, err
}

// Applications returns an object that can list and get Applications.
func (s *appLister) Applications(namespace string) applisters.ApplicationNamespaceLister {
	return applicationNamespaceLister{indexer: s.informer.GetIndexer(), namespace: namespace}
}

// FromInterface converts an interface to an application. The object may be one of:
// *unstructured.Unstructured or an *argoappv1.Application.
func FromInterface(obj interface{}) (*argoappv1.Application, error) {
	if un, ok := obj.(*unstructured.Unstructured); ok {
		return FromUnstructured(un)
	}
	if app, ok := obj.(*argoappv1.Application); ok {
		return app, nil
	}
	return nil, fmt.Errorf("object is neither an Unstructured or Application object")
}

// FromUnstructured converts an unstructured object to a application
func FromUnstructured(un *unstructured.Unstructured) (*argoappv1.Application, error) {
	var app argoappv1.Application
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, &app)
	return &app, err
}

// ToUnstructured converts an application to an Unstructured object
func ToUnstructured(app *argoappv1.Application) (*unstructured.Unstructured, error) {
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(app)
	return &unstructured.Unstructured{Object: obj}, err
}

// applicationNamespaceLister implements the ApplicationNamespaceLister
// interface.
type applicationNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all Applications in the indexer for a given namespace.
func (s applicationNamespaceLister) List(selector labels.Selector) ([]*argoappv1.Application, error) {
	var apps []*argoappv1.Application
	err := cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		app, err := FromUnstructured(m.(*unstructured.Unstructured))
		if err != nil {
			log.Warnf("Failed to unmarshal app %v object: %v", m, err)
		} else {
			apps = append(apps, app)
		}
	})
	return apps, err
}

// Get retrieves the Application from the indexer for a given namespace and name.
func (s applicationNamespaceLister) Get(name string) (*argoappv1.Application, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, apierr.NewNotFound(argoappv1.Resource("application"), name)
	}
	return FromUnstructured(obj.(*unstructured.Unstructured))
}
