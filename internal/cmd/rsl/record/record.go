// SPDX-License-Identifier: Apache-2.0

package record

import (
	"github.com/gittuf/gittuf/internal/cmd/common"
	"github.com/gittuf/gittuf/internal/repository"
	"github.com/spf13/cobra"
)

type options struct {
	dstRef string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.dstRef,
		"dst-ref",
		"",
		"name of destination reference, if it differs from source reference",
	)
}

func (o *options) Run(_ *cobra.Command, args []string) error {
	repo, err := repository.LoadRepository()
	if err != nil {
		return err
	}

	return repo.RecordRSLEntryForReference(args[0], o.dstRef, true)
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:               "record",
		Short:             "Record latest state of a Git reference in the RSL",
		Args:              cobra.ExactArgs(1),
		PreRunE:           common.CheckIfSigningViable,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
