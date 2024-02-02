package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiserrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/component-helpers/auth/rbac/validation"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"sigs.k8s.io/yaml"

	"github.com/joelanford/kubectl-make_rbac/internal/third_party/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

var (
	makeRBACExample = `

    # view all of the RBAC required for self to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml

    # view all of the RBAC required for user "some-user" to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --for some-user

    # view all of the RBAC required for group "some-group" to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --for-group some-group

    # view all of the RBAC required for service account "my-service-account" in namespace "my-namespace"
    # to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --for system:serviceaccount:my-namespace:my-service-account

    # view missing RBAC required for self to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --missing-only

    # view missing RBAC required for user "some-user" to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --missing-only --for some-user 

    # view missing RBAC required for group "some-group" to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --missing-only --for-group some-group

    # view missing RBAC required for service account "my-service-account" in namespace "my-namespace"
    # to manage objects from a given manifest
    kubectl make-rbac -f my-manifest.yaml --missing-only --for system:serviceaccount:my-namespace:my-service-account
`
)

// MakeRBACOptions provides information required to
// check missing RBAC rules
type MakeRBACOptions struct {
	FilenameOptions     resource.FilenameOptions
	ValidationDirective string

	RBACName    string
	For         string
	ForGroup    string
	MissingOnly bool

	genericiooptions.IOStreams
}

func NewMakeRBACOptions(streams genericiooptions.IOStreams) *MakeRBACOptions {
	return &MakeRBACOptions{
		IOStreams: streams,
	}
}

func NewCmdMakeRBAC(f cmdutil.Factory, ioStreams genericiooptions.IOStreams) *cobra.Command {
	o := NewMakeRBACOptions(ioStreams)

	cmd := &cobra.Command{
		Use:                   "kubectl make-rbac RBAC-NAME -f FILENAME",
		DisableFlagsInUseLine: true,
		Short:                 "View required RBAC required required to manage a given manifest",
		Long: `View required RBAC required required to manage a given manifest

This command evaluates the objects in the given manifest and produces
the RBAC required to manage them.

If the --for or --for-group flags are specified, make-rbac will produce
the RBAC required for the specified user, groups, or service account.

If the --missing-only flag is specified, make-rbac will produce RBAC for
permissions that the user does not already have.

Note that in order to make output more useful, make-rbac will also output
any required namespaces and service accounts unless both of:
  - they are present in the cluster
  - the --missing-only flag is specified
`,
		Example: makeRBACExample,
		Run: func(cmd *cobra.Command, args []string) {
			if cmdutil.IsFilenameSliceEmpty(o.FilenameOptions.Filenames, o.FilenameOptions.Kustomize) {
				ioStreams.ErrOut.Write([]byte("Error: must specify one of -f and -k\n\n"))
				defaultRunFunc := cmdutil.DefaultSubCommandRun(ioStreams.ErrOut)
				defaultRunFunc(cmd, args)
				return
			}
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Validate())
			cmdutil.CheckErr(o.RunMakeRBAC(f, cmd))
		},
	}
	usage := "to use to check missing RBAC rules required to create, update, delete, and patch the objects"
	cmdutil.AddFilenameOptionFlags(cmd, &o.FilenameOptions, usage)
	cmdutil.AddValidateFlags(cmd)

	cmd.Flags().StringVar(&o.For, "for", "", "View RBAC for the specified user or service account")
	cmd.Flags().StringVar(&o.For, "for-group", "", "View RBAC for the specified group")
	cmd.Flags().BoolVar(&o.MissingOnly, "missing-only", false, "Only output missing RBAC")

	return cmd
}

func (o *MakeRBACOptions) Complete(_ cmdutil.Factory, cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return cmdutil.UsageErrorf(cmd, "Unexpected args: %v", args)
	}
	o.RBACName = args[0]

	var err error
	o.ValidationDirective, err = cmdutil.GetValidationDirective(cmd)
	if err != nil {
		return err
	}

	return nil
}

func (o *MakeRBACOptions) Validate() error {
	if o.For != "" && o.ForGroup != "" {
		return fmt.Errorf("cannot specify --for and --for-group at the same time")
	}
	return nil
}

func (o *MakeRBACOptions) RunMakeRBAC(f cmdutil.Factory, cmd *cobra.Command) error {
	schema, err := f.Validator(o.ValidationDirective)
	if err != nil {
		return err
	}

	cmdNamespace, enforceNamespace, err := f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	r := f.NewBuilder().
		Unstructured().
		Schema(schema).
		ContinueOnError().
		NamespaceParam(cmdNamespace).DefaultNamespace().
		FilenameParam(enforceNamespace, &o.FilenameOptions).
		Flatten().
		Do()
	err = r.Err()
	if err != nil {
		return err
	}

	cs, err := f.KubernetesClientSet()
	if err != nil {
		return err
	}

	var subject rbacv1.Subject
	if o.For != "" {
		subject, err = userToSubject(o.For)
		if err != nil {
			return err
		}
	} else if o.ForGroup != "" {
		subject = rbacv1.Subject{Kind: "Group", Name: o.ForGroup}
	} else {
		ssr, err := cs.AuthenticationV1().SelfSubjectReviews().Create(cmd.Context(), &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		subject, err = userToSubject(ssr.Status.UserInfo.Username)
		if err != nil {
			return err
		}
	}

	var policyRules []rbacv1.PolicyRule
	if o.MissingOnly {
		cc, err := f.ToRESTConfig()
		if err != nil {
			return err
		}
		cc.Impersonate.UserName = o.For
		if o.ForGroup != "" {
			cc.Impersonate.Groups = []string{o.ForGroup}
		}

		impersonatedClientSet, err := kubernetes.NewForConfig(cc)
		if err != nil {
			return err
		}

		ssrr, err := impersonatedClientSet.AuthorizationV1().SelfSubjectRulesReviews().Create(cmd.Context(), &authzv1.SelfSubjectRulesReview{Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: cmdNamespace}}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		if ssrr.Status.Incomplete {
			return fmt.Errorf("selfsubjectrulesreviews is incomplete")
		}

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
	}

	count := 0
	namespaces := sets.New[string]()
	missingRules := map[string][]rbacv1.PolicyRule{}
	err = r.Visit(func(info *resource.Info, err error) error {
		if err != nil {
			return err
		}

		for _, verb := range []string{"create", "update", "delete", "patch"} {
			if !rbac.RulesAllow(authorizer.AttributesRecord{
				Verb:            verb,
				Name:            info.Name,
				Namespace:       info.Namespace,
				Resource:        info.Mapping.Resource.Resource,
				APIGroup:        info.Mapping.Resource.Group,
				ResourceRequest: true,
			}, policyRules...) {
				namespaces.Insert(info.Namespace)
				missingRules[info.Namespace] = append(missingRules[info.Namespace], rbacv1.PolicyRule{
					Verbs:         []string{verb},
					APIGroups:     []string{info.Mapping.Resource.Group},
					Resources:     []string{info.Mapping.Resource.Resource},
					ResourceNames: []string{info.Name},
				})
			}
		}

		if _, missing := validation.Covers(policyRules, getRoleRules(info)); len(missing) > 0 {
			for _, rule := range missing {
				namespaces.Insert(info.Namespace)
				missingRules[info.Namespace] = append(missingRules[info.Namespace], rule)
			}
		}

		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no objects passed to makerbac")
	}

	if subject.Namespace != "" {
		namespaces.Insert(subject.Namespace)
	}

	namespacesSorted := sets.List(namespaces)
	for _, ns := range namespacesSorted {
		if ns == "" {
			continue
		}
		nsExists, err := namespaceExists(cmd.Context(), cs, ns)
		if err != nil {
			return err
		}

		skipNamespace := o.MissingOnly && nsExists
		if !skipNamespace {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: ns,
				},
			}
			ns.APIVersion = "v1"
			ns.Kind = "Namespace"
			nsData, err := yaml.Marshal(ns)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(o.Out, "---\n%s", nsData); err != nil {
				return err
			}
		}
	}

	if subject.Kind == "ServiceAccount" {
		saExists, err := serviceAccountExists(cmd.Context(), cs, subject.Namespace, subject.Name)
		if err != nil {
			return err
		}

		skipServiceAccount := o.MissingOnly && saExists
		if !skipServiceAccount {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      subject.Name,
					Namespace: subject.Namespace,
				},
			}
			sa.APIVersion = "v1"
			sa.Kind = "ServiceAccount"
			saData, err := yaml.Marshal(sa)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(o.Out, "---\n%s", saData); err != nil {
				return err
			}
		}
	}

	for _, namespace := range namespacesSorted {
		rules, ok := missingRules[namespace]
		if !ok {
			continue
		}
		objectMeta := metav1.ObjectMeta{
			Name:      o.RBACName,
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
		if _, err := fmt.Fprintf(o.Out, "---\n%s\n---\n%s", roleData, roleBindingData); err != nil {
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

func userToSubject(user string) (rbacv1.Subject, error) {
	if !strings.HasPrefix(user, "system:serviceaccount:") {
		return rbacv1.Subject{Kind: "User", Name: user}, nil
	}

	saNamespace, saName, found := strings.Cut(strings.TrimPrefix(user, "system:serviceaccount:"), ":")
	if !found {
		return rbacv1.Subject{}, fmt.Errorf("invalid service account format: %q", user)
	}
	return rbacv1.Subject{Kind: "ServiceAccount", Name: saName, Namespace: saNamespace}, nil
}

func serviceAccountExists(ctx context.Context, cs *kubernetes.Clientset, namespace, name string) (bool, error) {
	_, err := cs.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apiserrors.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

func namespaceExists(ctx context.Context, cs *kubernetes.Clientset, namespace string) (bool, error) {
	_, err := cs.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apiserrors.IsNotFound(err) {
		return false, nil
	}
	return false, err
}
