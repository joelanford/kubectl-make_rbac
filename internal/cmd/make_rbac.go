package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/cli-runtime/pkg/resource"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/joelanford/kubectl-make_rbac/internal/version"
	makerbac "github.com/joelanford/kubectl-make_rbac/make-rbac"
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

	Name        string
	For         string
	ForGroup    string
	MissingOnly bool

	PrintVersionAndExit bool
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
			if o.PrintVersionAndExit {
				_, _ = fmt.Fprintf(ioStreams.Out, "%#v\n", version.Version)
				return
			}
			if cmdutil.IsFilenameSliceEmpty(o.FilenameOptions.Filenames, o.FilenameOptions.Kustomize) {
				_, _ = ioStreams.ErrOut.Write([]byte("Error: must specify one of -f and -k\n\n"))
				defaultRunFunc := cmdutil.DefaultSubCommandRun(ioStreams.ErrOut)
				defaultRunFunc(cmd, args)
				return
			}
			cmdutil.CheckErr(o.Complete(cmd))
			cmdutil.CheckErr(o.RunMakeRBAC(f, cmd))
		},
	}
	usage := "to use to check missing RBAC rules required to create, update, delete, and patch the objects"
	cmdutil.AddFilenameOptionFlags(cmd, &o.FilenameOptions, usage)
	cmdutil.AddValidateFlags(cmd)

	cmd.Flags().StringVar(&o.Name, "name", "", `The name to use for the generated RBAC (default: "make-rbac-<timestamp>")`)
	cmd.Flags().StringVar(&o.For, "for", "", "View RBAC for the specified user or service account")
	cmd.Flags().StringVar(&o.ForGroup, "for-group", "", "View RBAC for the specified group")
	cmd.MarkFlagsMutuallyExclusive("for", "for-group")
	cmd.Flags().BoolVar(&o.MissingOnly, "missing-only", false, "Only output missing RBAC")
	cmd.Flags().BoolVar(&o.PrintVersionAndExit, "version", false, "Print version information and quit")

	return cmd
}

func (o *MakeRBACOptions) Complete(cmd *cobra.Command) error {
	var err error
	o.ValidationDirective, err = cmdutil.GetValidationDirective(cmd)
	if err != nil {
		return fmt.Errorf("get validation directive: %v", err)
	}

	if o.Name == "" {
		o.Name = fmt.Sprintf("make-rbac-%s", time.Now().Format("20060102150405"))
	}

	return nil
}

func (o *MakeRBACOptions) RunMakeRBAC(f cmdutil.Factory, cmd *cobra.Command) error {
	schema, err := f.Validator(o.ValidationDirective)
	if err != nil {
		return err
	}

	cmdNamespace, _, err := f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	visitor := f.NewBuilder().
		Unstructured().
		Schema(schema).
		ContinueOnError().
		NamespaceParam(cmdNamespace).DefaultNamespace().
		FilenameParam(false, &o.FilenameOptions).
		Flatten().
		Do()
	err = visitor.Err()
	if err != nil {
		return err
	}

	restConfig, err := f.ToRESTConfig()
	if err != nil {
		return err
	}

	rbacFor, err := o.getFor()
	if err != nil {
		return err
	}

	mr := makerbac.MakeRBAC{
		Name:        o.Name,
		For:         rbacFor,
		MissingOnly: o.MissingOnly,
		Visitor:     visitor,
		Writer:      o.Out,
		Config:      restConfig,
	}
	return mr.Run(cmd.Context())
}

func (o *MakeRBACOptions) getFor() (makerbac.For, error) {
	if o.For != "" {
		return makerbac.ForUserOrServiceAccount(o.For)
	}
	if o.ForGroup != "" {
		return makerbac.ForGroup(o.ForGroup), nil
	}
	return nil, nil
}
