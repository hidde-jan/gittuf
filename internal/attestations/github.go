// SPDX-License-Identifier: Apache-2.0

package attestations

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"

	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v61/github"
	ita "github.com/in-toto/attestation/go/v1"
	sslibdsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	GitHubPullRequestPredicateType         = "https://gittuf.dev/github-pull-request/v0.1"
	GitHubPullRequestApprovalPredicateType = "https://gittuf.dev/github-pull-request-approval/v0.1"
	digestGitCommitKey                     = "gitCommit"
)

var (
	ErrInvalidGitHubPullRequestApprovalAttestation  = errors.New("the GitHub pull request approval attestation does not match expected details")
	ErrGitHubPullRequestApprovalAttestationNotFound = errors.New("requested GitHub pull request approval attestation not found")
)

func NewGitHubPullRequestAttestation(owner, repository string, pullRequestNumber int, commitID string, pullRequest *github.PullRequest) (*ita.Statement, error) {
	pullRequestBytes, err := json.Marshal(pullRequest)
	if err != nil {
		return nil, err
	}

	predicate := map[string]any{}
	if err := json.Unmarshal(pullRequestBytes, &predicate); err != nil {
		return nil, err
	}

	predicateStruct, err := structpb.NewStruct(predicate)
	if err != nil {
		return nil, err
	}

	return &ita.Statement{
		Type: ita.StatementTypeUri,
		Subject: []*ita.ResourceDescriptor{
			{
				Uri:    fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repository, pullRequestNumber),
				Digest: map[string]string{digestGitCommitKey: commitID},
			},
		},
		PredicateType: GitHubPullRequestPredicateType,
		Predicate:     predicateStruct,
	}, nil
}

func (a *Attestations) SetGitHubPullRequestAuthorization(repo *git.Repository, env *sslibdsse.Envelope, targetRefName, commitID string) error {
	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}

	blobID, err := gitinterface.WriteBlob(repo, envBytes)
	if err != nil {
		return err
	}

	if a.githubPullRequestAttestations == nil {
		a.githubPullRequestAttestations = map[string]plumbing.Hash{}
	}

	a.githubPullRequestAttestations[GitHubPullRequestAttestationPath(targetRefName, commitID)] = blobID
	return nil
}

// GitHubPullRequestAttestationPath constructs the expected path on-disk for the
// GitHub pull request attestation.
func GitHubPullRequestAttestationPath(refName, commitID string) string {
	return path.Join(refName, commitID)
}

type GitHubPullRequestApprovalAttestation struct {
	Approvers []*tuf.Key `json:"approvers"`
	*ReferenceAuthorization
}

func NewGitHubPullRequestApprovalAttestation(targetRef, fromRevisionID, targetTreeID string, approvers []*tuf.Key) (*ita.Statement, error) {
	sort.Slice(approvers, func(i, j int) bool {
		return approvers[i].KeyID < approvers[j].KeyID
	})

	predicate := &GitHubPullRequestApprovalAttestation{
		ReferenceAuthorization: &ReferenceAuthorization{
			TargetRef:      targetRef,
			FromRevisionID: fromRevisionID,
			TargetTreeID:   targetTreeID,
		},
		Approvers: approvers,
	}

	predicateStruct, err := predicateToPBStruct(predicate)
	if err != nil {
		return nil, err
	}

	return &ita.Statement{
		Type: ita.StatementTypeUri,
		Subject: []*ita.ResourceDescriptor{
			{
				Digest: map[string]string{digestGitTreeKey: targetTreeID},
			},
		},
		PredicateType: GitHubPullRequestApprovalPredicateType,
		Predicate:     predicateStruct,
	}, nil
}

func (a *Attestations) SetGitHubPullRequestApprovalAttestation(repo *git.Repository, env *sslibdsse.Envelope, refName, fromRevisionID, targetTreeID string) error {
	if err := validateGitHubPullRequestApprovalAttestation(env, refName, fromRevisionID, targetTreeID); err != nil {
		return errors.Join(ErrInvalidGitHubPullRequestApprovalAttestation, err)
	}

	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}

	blobID, err := gitinterface.WriteBlob(repo, envBytes)
	if err != nil {
		return err
	}

	if a.githubPullRequestApprovalAttestations == nil {
		a.githubPullRequestApprovalAttestations = map[string]plumbing.Hash{}
	}

	a.githubPullRequestApprovalAttestations[GitHubPullRequestApprovalAttestationPath(refName, fromRevisionID, targetTreeID)] = blobID
	return nil
}

func (a *Attestations) GetGitHubPullRequestApprovalAttestationFor(repo *git.Repository, refName, fromRevisionID, targetTreeID string) (*sslibdsse.Envelope, error) {
	blobID, has := a.githubPullRequestApprovalAttestations[GitHubPullRequestApprovalAttestationPath(refName, fromRevisionID, targetTreeID)]
	if !has {
		return nil, ErrGitHubPullRequestApprovalAttestationNotFound
	}

	envBytes, err := gitinterface.ReadBlob(repo, blobID)
	if err != nil {
		return nil, err
	}

	env := &sslibdsse.Envelope{}
	if err := json.Unmarshal(envBytes, env); err != nil {
		return nil, err
	}

	return env, nil
}

func GitHubPullRequestApprovalAttestationPath(refName, fromID, toID string) string {
	return ReferenceAuthorizationPath(refName, fromID, toID)
}

func validateGitHubPullRequestApprovalAttestation(env *sslibdsse.Envelope, targetRef, fromRevisionID, targetTreeID string) error {
	return validateReferenceAuthorization(env, targetRef, fromRevisionID, targetTreeID)
}
