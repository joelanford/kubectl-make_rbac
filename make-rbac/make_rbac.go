package makerbac

import (
	"context"
	"fmt"
	"io"
	"sync"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	clientauthzv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	rbacvalidation "k8s.io/component-helpers/auth/rbac/validation"
	"sigs.k8s.io/yaml"

	"github.com/joelanford/kubectl-make_rbac/internal/third_party/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

type MakeRBAC struct {
	Name        string
	For         For
	MissingOnly bool

	Visitor resource.Visitor
	Writer  io.Writer

	Config *rest.Config
}

func (m *MakeRBAC) Run(ctx context.Context) error {
	cs, err := kubernetes.NewForConfig(m.Config)
	if err != nil {
		return err
	}

	var (
		subject    rbacv1.Subject
		ssrrClient = cs.AuthorizationV1().SelfSubjectRulesReviews()
	)
	if m.For != nil {
		impersonateConfig := rest.CopyConfig(m.Config)
		m.For.ImpersonateConfig(&impersonateConfig.Impersonate)
		impersonateClientSet, err := kubernetes.NewForConfig(impersonateConfig)
		if err != nil {
			return err
		}
		subject = m.For.Subject()
		ssrrClient = impersonateClientSet.AuthorizationV1().SelfSubjectRulesReviews()
	} else {
		ssr, err := cs.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		subjFor, err := ForUserOrServiceAccount(ssr.Status.UserInfo.Username)
		if err != nil {
			return err
		}
		subject = subjFor.Subject()
	}

	count := 0
	namespaces := sets.New[string]()
	ownerRulesCache := &ownerRulesCache{rulesByNamespace: map[string][]rbacv1.PolicyRule{}, ssrrClient: ssrrClient}
	missingRulesByNamespace := map[string][]rbacv1.PolicyRule{}
	err = m.Visitor.Visit(func(info *resource.Info, err error) error {
		if err != nil {
			return err
		}

		if info.Mapping.Scope == meta.RESTScopeNamespace && info.Namespace == "" {
			return fmt.Errorf("namespace is required for %s %q", info.Mapping.Resource.Resource, info.Name)
		}

		var ownerRules []rbacv1.PolicyRule
		if m.MissingOnly {
			ownerRules, err = ownerRulesCache.Get(ctx, info.Namespace)
			if err != nil {
				return err
			}
		}

		for _, verb := range []string{"create", "update", "delete", "patch"} {
			if !rbac.RulesAllow(authorizer.AttributesRecord{
				Verb:            verb,
				Name:            info.Name,
				Namespace:       info.Namespace,
				Resource:        info.Mapping.Resource.Resource,
				APIGroup:        info.Mapping.Resource.Group,
				ResourceRequest: true,
			}, ownerRules...) {
				namespaces.Insert(info.Namespace)
				missingRulesByNamespace[info.Namespace] = append(missingRulesByNamespace[info.Namespace], rbacv1.PolicyRule{
					Verbs:         []string{verb},
					APIGroups:     []string{info.Mapping.Resource.Group},
					Resources:     []string{info.Mapping.Resource.Resource},
					ResourceNames: []string{info.Name},
				})
			}
		}

		if _, missing := rbacvalidation.Covers(ownerRules, getRoleRules(info)); len(missing) > 0 {
			for _, rule := range missing {
				namespaces.Insert(info.Namespace)
				missingRulesByNamespace[info.Namespace] = append(missingRulesByNamespace[info.Namespace], rule)
			}
		}

		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no objects visited")
	}

	if subject.Namespace != "" {
		namespaces.Insert(subject.Namespace)
	}

	corev1ClientSet := cs.CoreV1()
	namespacesSorted := sets.List(namespaces)
	for _, ns := range namespacesSorted {
		if ns == "" {
			continue
		}
		nsExists, err := namespaceExists(ctx, corev1ClientSet, ns)
		if err != nil {
			return err
		}

		skipNamespace := m.MissingOnly && nsExists
		if !skipNamespace {
			if err := writeNamespace(m.Writer, ns); err != nil {
				return err
			}
		}
	}

	if subject.Kind == "ServiceAccount" {
		saExists, err := serviceAccountExists(ctx, corev1ClientSet, subject.Namespace, subject.Name)
		if err != nil {
			return err
		}

		skipServiceAccount := m.MissingOnly && saExists
		if !skipServiceAccount {
			if err := writeServiceAccount(m.Writer, subject.Namespace, subject.Name); err != nil {
				return err
			}
		}
	}

	for _, namespace := range namespacesSorted {
		rules, ok := missingRulesByNamespace[namespace]
		if !ok {
			continue
		}
		objectMeta := metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: namespace,
		}
		var (
			r  runtime.Object
			rb runtime.Object
		)
		switch namespace {
		case "":
			r = &rbacv1.ClusterRole{ObjectMeta: objectMeta, Rules: rules}
			r.GetObjectKind().SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRole"))
			rb = &rbacv1.ClusterRoleBinding{ObjectMeta: objectMeta, Subjects: []rbacv1.Subject{subject}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: objectMeta.Name}}
			rb.GetObjectKind().SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"))
		default:
			r = &rbacv1.Role{ObjectMeta: objectMeta, Rules: rules}
			r.GetObjectKind().SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("Role"))
			rb = &rbacv1.RoleBinding{ObjectMeta: objectMeta, Subjects: []rbacv1.Subject{subject}, RoleRef: rbacv1.RoleRef{Kind: "Role", Name: objectMeta.Name}}
			rb.GetObjectKind().SetGroupVersionKind(rbacv1.SchemeGroupVersion.WithKind("RoleBinding"))
		}
		roleData, err := yaml.Marshal(r)
		if err != nil {
			return err
		}
		roleBindingData, err := yaml.Marshal(rb)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(m.Writer, "---\n%s\n---\n%s", roleData, roleBindingData); err != nil {
			return err
		}
	}

	return nil
}

func getRoleRules(info *resource.Info) []rbacv1.PolicyRule {
	switch info.Mapping.Resource.GroupResource().String() {
	case "roles.rbac.authorization.k8s.io":
		var r rbacv1.Role
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(info.Object.(*unstructured.Unstructured).Object, &r); err != nil {
			return nil
		}
		return r.Rules
	case "clusterroles.rbac.authorization.k8s.io":
		var r rbacv1.ClusterRole
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(info.Object.(*unstructured.Unstructured).Object, &r); err != nil {
			return nil
		}
		return r.Rules
	default:
		return nil
	}
}

func serviceAccountExists(ctx context.Context, serviceAccountsGetter clientcorev1.ServiceAccountsGetter, namespace, name string) (bool, error) {
	_, err := serviceAccountsGetter.ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

func writeServiceAccount(w io.Writer, namespace, name string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	sa.APIVersion = "v1"
	sa.Kind = "ServiceAccount"
	saData, err := yaml.Marshal(sa)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "---\n%s", saData); err != nil {
		return err
	}
	return nil
}

func namespaceExists(ctx context.Context, namespacesGetter clientcorev1.NamespacesGetter, namespace string) (bool, error) {
	_, err := namespacesGetter.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

func writeNamespace(w io.Writer, namespace string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	ns.APIVersion = "v1"
	ns.Kind = "Namespace"
	nsData, err := yaml.Marshal(ns)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "---\n%s", nsData); err != nil {
		return err
	}
	return nil
}

type ownerRulesCache struct {
	rulesByNamespace map[string][]rbacv1.PolicyRule
	ssrrClient       clientauthzv1.SelfSubjectRulesReviewInterface
	m                sync.Mutex
}

func (c *ownerRulesCache) Get(ctx context.Context, namespace string) ([]rbacv1.PolicyRule, error) {
	c.m.Lock()
	defer c.m.Unlock()
	rules, ok := c.rulesByNamespace[namespace]
	if ok {
		return rules, nil
	}
	rulesNamespace := namespace
	if namespace == "" {
		// There is not an API to get the selfsubjectrulesreview (SSRR) for the cluster scope,
		// so we use the default namespace in our request. Since `info` is a cluster-scoped
		// object and SSRR includes cluster-scoped rules, we can use any namespace that we know
		// exists. The fact that the returned rules also contain permissions for namespace-scoped
		// objects in the default namespace is not a problem, since we will never use them to check
		// against a namespace-scoped object.
		rulesNamespace = "default"
	}
	rules, err := userRulesInNamespace(ctx, c.ssrrClient, rulesNamespace)
	if err != nil {
		return nil, err
	}
	c.rulesByNamespace[namespace] = rules
	return rules, nil
}

func userRulesInNamespace(ctx context.Context, ssrrClient clientauthzv1.SelfSubjectRulesReviewInterface, namespace string) ([]rbacv1.PolicyRule, error) {
	ssrr, err := ssrrClient.Create(ctx, &authorizationv1.SelfSubjectRulesReview{Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: namespace}}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("selfsubjectrulesreview: %v", err)
	}
	if ssrr.Status.Incomplete {
		return nil, fmt.Errorf("selfsubjectrulesreviews is incomplete")
	}

	policyRules := make([]rbacv1.PolicyRule, 0, len(ssrr.Status.ResourceRules)+len(ssrr.Status.NonResourceRules))
	for _, rule := range ssrr.Status.ResourceRules {
		policyRules = append(policyRules, rbacv1.PolicyRule{
			Verbs:         rule.Verbs,
			APIGroups:     rule.APIGroups,
			Resources:     rule.Resources,
			ResourceNames: rule.ResourceNames,
		})
	}
	for _, rule := range ssrr.Status.NonResourceRules {
		policyRules = append(policyRules, rbacv1.PolicyRule{
			Verbs:           rule.Verbs,
			NonResourceURLs: rule.NonResourceURLs,
		})
	}
	return policyRules, nil
}
