// SPDX-License-Identifier: Apache-2.0

package attestations

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	ita "github.com/in-toto/attestation/go/v1"
	sslibdsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	ReferenceAuthorizationPredicateType = "https://gittuf.dev/reference-authorization/v0.1"
	digestGitTreeKey                    = "gitTree"
	targetRefKey                        = "targetRef"
	fromRevisionIDKey                   = "fromRevisionID"
	targetTreeIDKey                     = "targetTreeID"
)

var (
	ErrInvalidAuthorization  = errors.New("authorization attestation does not match expected details")
	ErrAuthorizationNotFound = errors.New("requested authorization not found")
)

// ReferenceAuthorization is a lightweight record of a detached authorization in
// a gittuf repository. It is meant to be used as a "predicate" in an in-toto
// attestation.
type ReferenceAuthorization struct {
	TargetRef      string `json:"targetRef"`
	FromRevisionID string `json:"fromRevisionID"`
	TargetTreeID   string `json:"targetTreeID"`
}

// NewReferenceAuthorization creates a new reference authorization for the
// provided information. The authorization is embedded in an in-toto "statement"
// and returned with the appropriate "predicate type" set. The `fromTargetID`
// and `toTargetID` specify the change to `targetRef` that is to be authorized
// by invoking this function.
func NewReferenceAuthorization(targetRef, fromRevisionID, targetTreeID string) (*ita.Statement, error) {
	predicate := &ReferenceAuthorization{
		TargetRef:      targetRef,
		FromRevisionID: fromRevisionID,
		TargetTreeID:   targetTreeID,
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
		PredicateType: ReferenceAuthorizationPredicateType,
		Predicate:     predicateStruct,
	}, nil
}

// SetReferenceAuthorization writes the new reference authorization attestation
// to the object store and tracks it in the current attestations state.
func (a *Attestations) SetReferenceAuthorization(repo *git.Repository, env *sslibdsse.Envelope, refName, fromRevisionID, targetTreeID string) error {
	if err := validateReferenceAuthorization(env, refName, fromRevisionID, targetTreeID); err != nil {
		return err
	}

	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}

	blobID, err := gitinterface.WriteBlob(repo, envBytes)
	if err != nil {
		return err
	}

	if a.referenceAuthorizations == nil {
		a.referenceAuthorizations = map[string]plumbing.Hash{}
	}

	a.referenceAuthorizations[ReferenceAuthorizationPath(refName, fromRevisionID, targetTreeID)] = blobID
	return nil
}

// RemoveReferenceAuthorization removes a set reference authorization
// attestation entirely. The object, however, isn't removed from the object
// store as prior states may still need it.
func (a *Attestations) RemoveReferenceAuthorization(refName, fromRevisionID, targetTreeID string) error {
	authPath := ReferenceAuthorizationPath(refName, fromRevisionID, targetTreeID)
	if _, has := a.referenceAuthorizations[authPath]; !has {
		return ErrAuthorizationNotFound
	}

	delete(a.referenceAuthorizations, authPath)
	return nil
}

// GetReferenceAuthorizationFor returns the requested reference authorization
// attestation (with its signatures).
func (a *Attestations) GetReferenceAuthorizationFor(repo *git.Repository, refName, fromRevisionID, targetTreeID string) (*sslibdsse.Envelope, error) {
	blobID, has := a.referenceAuthorizations[ReferenceAuthorizationPath(refName, fromRevisionID, targetTreeID)]
	if !has {
		return nil, ErrAuthorizationNotFound
	}

	envBytes, err := gitinterface.ReadBlob(repo, blobID)
	if err != nil {
		return nil, err
	}

	env := &sslibdsse.Envelope{}
	if err := json.Unmarshal(envBytes, env); err != nil {
		return nil, err
	}

	if err := validateReferenceAuthorization(env, refName, fromRevisionID, targetTreeID); err != nil {
		return nil, err
	}

	return env, nil
}

// ReferenceAuthorizationPath constructs the expected path on-disk for the
// reference authorization attestation.
func ReferenceAuthorizationPath(refName, fromID, toID string) string {
	return path.Join(refName, fmt.Sprintf("%s-%s", fromID, toID))
}

func validateReferenceAuthorization(env *sslibdsse.Envelope, targetRef, fromRevisionID, targetTreeID string) error {
	payload, err := env.DecodeB64Payload()
	if err != nil {
		return err
	}

	attestation := &ita.Statement{}
	if err := json.Unmarshal(payload, attestation); err != nil {
		return err
	}

	if attestation.Subject[0].Digest[digestGitTreeKey] != targetTreeID {
		return ErrInvalidAuthorization
	}

	predicate := attestation.Predicate.AsMap()

	if predicate[targetTreeIDKey] != targetTreeID {
		return ErrInvalidAuthorization
	}

	if predicate[fromRevisionIDKey] != fromRevisionID {
		return ErrInvalidAuthorization
	}

	if predicate[targetRefKey] != targetRef {
		return ErrInvalidAuthorization
	}

	return nil
}
