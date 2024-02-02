package main

import (
	"os"

	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/joelanford/kubectl-make_rbac/internal/cmd"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-make_rbac", pflag.ExitOnError)
	pflag.CommandLine = flags

	ioStreams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}

	configFlags := genericclioptions.NewConfigFlags(true).
		WithDiscoveryBurst(300).
		WithDiscoveryQPS(50.0).WithWarningPrinter(ioStreams)

	configFlags.Impersonate = nil
	configFlags.ImpersonateGroup = nil
	configFlags.ImpersonateUID = nil
	configFlags.AddFlags(flags)

	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(configFlags)
	matchVersionKubeConfigFlags.AddFlags(flags)

	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	root := cmd.NewCmdMakeRBAC(f, ioStreams)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
