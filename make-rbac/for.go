package makerbac

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/rest"
)

type For interface {
	ImpersonateConfig(f *rest.ImpersonationConfig)
	Subject() rbacv1.Subject
}

func ForUser(name string) For {
	return user{name: name}
}

type user struct {
	name string
}

func (u user) ImpersonateConfig(f *rest.ImpersonationConfig) {
	f.UserName = u.name
}

func (u user) Subject() rbacv1.Subject {
	return rbacv1.Subject{Kind: "User", Name: u.name}
}

func ForGroup(name string) For {
	return group{name: name}
}

type group struct {
	name string
}

func (g group) ImpersonateConfig(f *rest.ImpersonationConfig) {
	f.Groups = []string{g.name}
}

func (g group) Subject() rbacv1.Subject {
	return rbacv1.Subject{Kind: "Group", Name: g.name}
}

func ForServiceAccount(namespace, name string) For {
	return serviceAccount{namespace: namespace, name: name}
}

type serviceAccount struct {
	namespace string
	name      string
}

func (sa serviceAccount) ImpersonateConfig(f *rest.ImpersonationConfig) {
	f.UserName = fmt.Sprintf("system:serviceaccount:%s:%s", sa.namespace, sa.name)
}

func (sa serviceAccount) Subject() rbacv1.Subject {
	return rbacv1.Subject{Kind: "ServiceAccount", Namespace: sa.namespace, Name: sa.name}
}

func ForUserOrServiceAccount(name string) (For, error) {
	if !strings.HasPrefix(name, "system:serviceaccount:") {
		return ForUser(name), nil
	}
	saNamespace, saName, ok := strings.Cut(strings.TrimPrefix(name, "system:serviceaccount:"), ":")
	if !ok {
		return nil, fmt.Errorf("invalid service account name %q", name)
	}
	return ForServiceAccount(saNamespace, saName), nil
}
