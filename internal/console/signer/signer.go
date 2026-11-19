// Package signer implements openrmm-signer: the only holder of the job
// signing key. It signs a job only if the request carries an id_token that
//
//   - is valid (signature, issuer, audience, expiry) for the console app,
//   - was issued with multi-factor authentication, recently,
//   - has a nonce equal to the canonical hash of this exact request,
//   - has never been used before,
//   - belongs to an operator allowed on the request's tenant, with an app
//     role that permits the request.
//
// The token may come from the console's own directory or, when federation
// is configured on the signer, from the central console's directory (with
// its roles capped by the federation's maximum role).
//
// App roles may be limited to client or server computers
// (OpenRMM.Operator.Clients, OpenRMM.Admin.Servers...): the signer then
// requires that limit in the request and copies it into every job, and the
// agent refuses a job for another OS family.
//
// A permanent workflow assignment (SignAssignment, SignAssignmentRun) is the
// one case where a job runs on the signer's own say-so afterwards: an
// administrator still approves the assignment itself the same way, with a
// fresh MFA token bound to its exact content, but once signed it is reused
// to issue jobs for the targets the console names later, until it expires.
//
// None of this depends on the console being honest.
package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/assignreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/profilereq"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/policy"
	"github.com/stefanozanarini/tempra-rmm/internal/signing"
)

// Server implements openrmmv1.SignerServiceServer.
type Server struct {
	openrmmv1.UnimplementedSignerServiceServer

	signer    *signing.Signer
	verifiers authn.Set
	log       *slog.Logger
	now       func() time.Time
	used      *usedTokens
}

// New returns a signer. stateFile persists the used-token register.
func New(signer *signing.Signer, verifier *authn.Verifier, stateFile string, log *slog.Logger) (*Server, error) {
	used, err := loadUsed(stateFile)
	if err != nil {
		return nil, err
	}
	return &Server{signer: signer, verifiers: authn.Set{verifier}, log: log, now: time.Now, used: used}, nil
}

// Trust also accepts operators of a central console's directory.
func (s *Server) Trust(v *authn.Verifier) { s.verifiers = append(s.verifiers, v) }

// verify checks a token with the verifier of its issuer.
func (s *Server) verify(ctx context.Context, raw string) (*authn.Claims, *authn.Verifier, error) {
	v := s.verifiers.For(raw)
	if v == nil {
		return nil, nil, errors.New("token issuer not trusted")
	}
	c, err := v.Verify(ctx, raw)
	return c, v, err
}

// SignJob verifies the operator's approval and signs the job.
func (s *Server) SignJob(ctx context.Context, req *openrmmv1.SignJobRequest) (*openrmmv1.SignJobResponse, error) {
	r := req.GetRequest()
	deny := func(reason string, err error) (*openrmmv1.SignJobResponse, error) {
		s.log.Warn("signature refused", "reason", reason, "err", err, "tenant", r.GetTenantId(),
			"agent", r.GetAgentId(), "module", r.GetModule(), "action", r.GetAction())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	if err := jobreq.Validate(r); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	claims, v, err := s.verify(ctx, req.GetIdToken())
	if err != nil {
		return deny("operator authentication rejected", err)
	}
	now := s.now()
	if err := v.CheckFresh(claims, now); err != nil {
		return deny("authentication too old", err)
	}
	if !jobreq.CheckAuthNonce(claims.Nonce, r) {
		return deny("authentication was not issued for this request", authn.ErrNonce)
	}
	if !v.MayManage(claims, r.GetTenantId()) {
		return deny("operator may not manage this tenant", authn.ErrNoTenant)
	}
	a := v.Access(claims)
	if err := allowFamily(a, authn.RoleOperator, r.GetOsFamily()); err != nil {
		return deny("operator may not run jobs on these computers", err)
	}
	// One authentication approves one job.
	if err := s.used.add(claims.Nonce, now.Add(2*time.Hour), now); err != nil {
		return deny("authentication already used", err)
	}

	return s.issue(r, operatorOf(claims, v)+" as "+describe(a), now)
}

// issue signs one job per target of r.
func (s *Server) issue(r *openrmmv1.JobRequest, op string, now time.Time) (*openrmmv1.SignJobResponse, error) {
	ttl := time.Duration(r.GetTtlSeconds()) * time.Second
	resp := &openrmmv1.SignJobResponse{Operator: op}
	for _, agent := range jobreq.Targets(r) {
		job := &openrmmv1.Job{
			JobId: ids.NewUUID(), TenantId: r.GetTenantId(), AgentId: agent,
			Module: r.GetModule(), ModuleVersion: r.GetModuleVersion(), ModuleSha256: r.GetModuleSha256(),
			Action: r.GetAction(), ParamsJson: r.GetParamsJson(), Packages: r.GetPackages(),
			OsFamily: r.GetOsFamily(),
			// The window starts a minute early for clock skew and lasts
			// exactly ttl: agents refuse windows longer than 48 hours (24 before 1.1.2).
			NotBeforeUnix: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(-time.Minute).Add(ttl).Unix(),
			Nonce: ids.Random(16),
		}
		payload, err := proto.Marshal(job)
		if err != nil {
			return nil, status.Error(codes.Internal, "encode job")
		}
		env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: payload,
			Signature: s.signer.Sign(signing.DomainJob, payload)})
		if err != nil {
			return nil, status.Error(codes.Internal, "encode envelope")
		}
		resp.Jobs = append(resp.Jobs, &openrmmv1.SignedJob{JobId: job.GetJobId(), AgentId: agent, Envelope: env})
		resp.ExpiresUnix = job.GetExpiresUnix()
		// The signer's own log is an audit trail independent of the console.
		s.log.Info("job signed", "job", job.GetJobId(), "operator", op, "tenant", r.GetTenantId(), "agent", agent,
			"module", r.GetModule(), "version", r.GetModuleVersion(), "action", r.GetAction(),
			"params_sha256", fmt.Sprintf("%x", sha256.Sum256(r.GetParamsJson())), "packages", len(r.GetPackages()))
	}
	if len(resp.Jobs) == 1 {
		resp.JobId, resp.Envelope = resp.Jobs[0].GetJobId(), resp.Jobs[0].GetEnvelope()
	}
	return resp, nil
}

// MaxCollectTTL bounds an on-demand collection.
const MaxCollectTTL = time.Hour

// SignCollect signs an on-demand run of a standard collection (inventory,
// update scans, protection status...) without an operator, like the
// automatic collection: only the read-only actions of policy.BaselineRules,
// without parameters or packages, for at most an hour, in a tenant of this
// console. What runs is still pinned to a module signed with the module key.
func (s *Server) SignCollect(_ context.Context, req *openrmmv1.SignCollectRequest) (*openrmmv1.SignJobResponse, error) {
	r := req.GetRequest()
	if err := jobreq.Validate(r); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	deny := func(reason string) (*openrmmv1.SignJobResponse, error) {
		s.log.Warn("collection refused", "reason", reason, "tenant", r.GetTenantId(), "module", r.GetModule(), "action", r.GetAction())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	if !s.ownTenant(r.GetTenantId()) {
		return deny("tenant not managed by this console")
	}
	if !policy.IsCollection(r.GetModule(), r.GetAction()) {
		return deny("not a standard collection")
	}
	if p := string(r.GetParamsJson()); p != "" && p != "{}" {
		return deny("collections take no parameters")
	}
	if len(r.GetPackages()) > 0 || time.Duration(r.GetTtlSeconds())*time.Second > MaxCollectTTL {
		return deny("collections carry no packages and last at most an hour")
	}
	return s.issue(r, "automatic (collection)", s.now())
}

// SignAssignment verifies an administrator's fresh MFA approval of a
// permanent workflow assignment and signs it. Unlike SignJob, this
// signature is not single-use for running jobs: SignAssignmentRun reuses it,
// without an operator, until it expires (AssignmentRequest.expires_unix).
// The one-time step-up token is still consumed here, like any other
// approval, so it cannot also approve something else.
func (s *Server) SignAssignment(ctx context.Context, req *openrmmv1.SignAssignmentRequest) (*openrmmv1.SignAssignmentResponse, error) {
	r := req.GetRequest()
	deny := func(reason string, err error) (*openrmmv1.SignAssignmentResponse, error) {
		s.log.Warn("assignment signature refused", "reason", reason, "err", err, "tenant", r.GetTenantId(),
			"workflow", r.GetWorkflowId())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	now := s.now()
	if err := assignreq.Validate(r, now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	claims, v, err := s.verify(ctx, req.GetIdToken())
	if err != nil {
		return deny("operator authentication rejected", err)
	}
	if err := v.CheckFresh(claims, now); err != nil {
		return deny("authentication too old", err)
	}
	if !assignreq.CheckAuthNonce(claims.Nonce, r) {
		return deny("authentication was not issued for this assignment", authn.ErrNonce)
	}
	// A permanent assignment runs unattended for its whole validity, so it
	// needs the Admin role.
	if !v.MayManage(claims, r.GetTenantId()) {
		return deny("operator may not manage this tenant", authn.ErrNoTenant)
	}
	a := v.Access(claims)
	if err := allowFamily(a, authn.RoleAdmin, r.GetOsFamily()); err != nil {
		return deny("only administrators of these computers may approve a permanent assignment", err)
	}
	if err := s.used.add(claims.Nonce, now.Add(2*time.Hour), now); err != nil {
		return deny("authentication already used", err)
	}
	payload, err := proto.Marshal(r)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode assignment")
	}
	env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: payload,
		Signature: s.signer.Sign(signing.DomainAssignment, payload)})
	if err != nil {
		return nil, status.Error(codes.Internal, "encode envelope")
	}
	op := operatorOf(claims, v) + " as " + describe(a)
	s.log.Info("assignment signed", "workflow", r.GetWorkflowId(), "revision", r.GetRevision(), "tenant", r.GetTenantId(),
		"operator", op, "expires_unix", r.GetExpiresUnix())
	return &openrmmv1.SignAssignmentResponse{Envelope: env, Operator: op, ExpiresUnix: r.GetExpiresUnix()}, nil
}

// SignAssignmentRun issues signed jobs for an already-approved assignment,
// without an operator: it verifies its own earlier signature over the
// assignment instead of a fresh id_token, and that the assignment has not
// expired. The console decides which targets are due for a run; this call
// cannot change the module, action, parameters or packages approved in the
// assignment, only the targets and a ttl capped by it.
func (s *Server) SignAssignmentRun(_ context.Context, req *openrmmv1.SignAssignmentRunRequest) (*openrmmv1.SignJobResponse, error) {
	deny := func(reason string, err error) (*openrmmv1.SignJobResponse, error) {
		s.log.Warn("assignment run refused", "reason", reason, "err", err)
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	env := &openrmmv1.SignedEnvelope{}
	if err := proto.Unmarshal(req.GetAssignmentEnvelope(), env); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid assignment envelope")
	}
	if err := s.signer.Verify(signing.DomainAssignment, env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		return deny("assignment envelope does not carry a valid signature of this signer", err)
	}
	r := &openrmmv1.AssignmentRequest{}
	if err := proto.Unmarshal(env.GetPayload(), r); err != nil {
		return nil, status.Error(codes.Internal, "decode assignment")
	}
	now := s.now()
	if err := assignreq.Validate(r, now); err != nil {
		// The signer's own earlier output, so a failure here means its
		// validation rules changed incompatibly since it was signed.
		return deny("signed assignment no longer valid", err)
	}
	if now.Unix() >= r.GetExpiresUnix() {
		return deny("assignment expired", fmt.Errorf("expired at %d", r.GetExpiresUnix()))
	}
	if err := assignreq.ValidateTargets(req.GetAgentIds(), assignreq.MaxAgents); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	ttl := req.GetTtlSeconds()
	if ttl < 60 || ttl > r.GetMaxTtlSeconds() {
		return nil, status.Error(codes.InvalidArgument, "ttl must be between 1 minute and the assignment's maximum")
	}
	jr := &openrmmv1.JobRequest{TenantId: r.GetTenantId(), AgentIds: req.GetAgentIds(), Module: r.GetModule(),
		ModuleVersion: r.GetModuleVersion(), ModuleSha256: r.GetModuleSha256(), Action: r.GetAction(),
		ParamsJson: r.GetParamsJson(), TtlSeconds: ttl, RequestNonce: jobreq.NewRequestNonce(), Packages: r.GetPackages(),
		OsFamily: r.GetOsFamily()}
	if len(jr.AgentIds) == 1 {
		jr.AgentId, jr.AgentIds = jr.AgentIds[0], nil
	}
	if err := jobreq.Validate(jr); err != nil {
		return nil, status.Error(codes.Internal, "built an invalid job: "+err.Error())
	}
	return s.issue(jr, fmt.Sprintf("automatic (workflow assignment, workflow %s rev. %d)", r.GetWorkflowId(), r.GetRevision()), now)
}

// SignProfile verifies an administrator's fresh MFA approval of a version
// of a provisioning profile and signs it. Like SignAssignment, the
// signature is then reused by SignProfileRun, without an operator, until
// it expires.
func (s *Server) SignProfile(ctx context.Context, req *openrmmv1.SignProfileRequest) (*openrmmv1.SignProfileResponse, error) {
	r := req.GetRequest()
	deny := func(reason string, err error) (*openrmmv1.SignProfileResponse, error) {
		s.log.Warn("profile signature refused", "reason", reason, "err", err, "tenant", r.GetTenantId(),
			"profile", r.GetProfileId())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	now := s.now()
	if err := profilereq.Validate(r, now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	claims, v, err := s.verify(ctx, req.GetIdToken())
	if err != nil {
		return deny("operator authentication rejected", err)
	}
	if err := v.CheckFresh(claims, now); err != nil {
		return deny("authentication too old", err)
	}
	if !profilereq.CheckAuthNonce(claims.Nonce, r) {
		return deny("authentication was not issued for this profile", authn.ErrNonce)
	}
	// A profile runs unattended for its whole validity, so it needs the
	// Admin role, like a permanent assignment.
	if !v.MayManage(claims, r.GetTenantId()) {
		return deny("operator may not manage this tenant", authn.ErrNoTenant)
	}
	a := v.Access(claims)
	if err := allowFamily(a, authn.RoleAdmin, r.GetOsFamily()); err != nil {
		return deny("only administrators of these computers may approve a provisioning profile", err)
	}
	if err := s.used.add(claims.Nonce, now.Add(2*time.Hour), now); err != nil {
		return deny("authentication already used", err)
	}
	payload, err := proto.Marshal(r)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode profile")
	}
	env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: payload,
		Signature: s.signer.Sign(signing.DomainProfile, payload)})
	if err != nil {
		return nil, status.Error(codes.Internal, "encode envelope")
	}
	op := operatorOf(claims, v) + " as " + describe(a)
	s.log.Info("profile signed", "profile", r.GetProfileId(), "version", r.GetVersion(), "tenant", r.GetTenantId(),
		"steps", len(r.GetSteps()), "operator", op, "expires_unix", r.GetExpiresUnix())
	return &openrmmv1.SignProfileResponse{Envelope: env, Operator: op, ExpiresUnix: r.GetExpiresUnix()}, nil
}

// SignProfileRun issues the signed jobs of one step of an already-approved
// profile, without an operator: it verifies its own earlier signature over
// the profile and that the approval has not expired. The console decides
// which step is due on which computers; this call cannot change what a step
// runs, only the targets and a ttl capped by the profile.
func (s *Server) SignProfileRun(_ context.Context, req *openrmmv1.SignProfileRunRequest) (*openrmmv1.SignJobResponse, error) {
	deny := func(reason string, err error) (*openrmmv1.SignJobResponse, error) {
		s.log.Warn("profile run refused", "reason", reason, "err", err)
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	env := &openrmmv1.SignedEnvelope{}
	if err := proto.Unmarshal(req.GetProfileEnvelope(), env); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile envelope")
	}
	if err := s.signer.Verify(signing.DomainProfile, env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		return deny("profile envelope does not carry a valid signature of this signer", err)
	}
	r := &openrmmv1.ProfileRequest{}
	if err := proto.Unmarshal(env.GetPayload(), r); err != nil {
		return nil, status.Error(codes.Internal, "decode profile")
	}
	now := s.now()
	if err := profilereq.Validate(r, now); err != nil {
		return deny("signed profile no longer valid", err)
	}
	if now.Unix() >= r.GetExpiresUnix() {
		return deny("profile approval expired", fmt.Errorf("expired at %d", r.GetExpiresUnix()))
	}
	i := int(req.GetStep())
	if i < 0 || i >= len(r.GetSteps()) {
		return nil, status.Error(codes.InvalidArgument, "no such step")
	}
	if err := assignreq.ValidateTargets(req.GetAgentIds(), profilereq.MaxAgents); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	ttl := req.GetTtlSeconds()
	if ttl < 60 || ttl > r.GetMaxTtlSeconds() {
		return nil, status.Error(codes.InvalidArgument, "ttl must be between 1 minute and the profile's maximum")
	}
	st := r.GetSteps()[i]
	jr := &openrmmv1.JobRequest{TenantId: r.GetTenantId(), AgentIds: req.GetAgentIds(), Module: st.GetModule(),
		ModuleVersion: st.GetModuleVersion(), ModuleSha256: st.GetModuleSha256(), Action: st.GetAction(),
		ParamsJson: st.GetParamsJson(), TtlSeconds: ttl, RequestNonce: jobreq.NewRequestNonce(), Packages: st.GetPackages(),
		OsFamily: r.GetOsFamily()}
	if len(jr.AgentIds) == 1 {
		jr.AgentId, jr.AgentIds = jr.AgentIds[0], nil
	}
	if err := jobreq.Validate(jr); err != nil {
		return nil, status.Error(codes.Internal, "built an invalid job: "+err.Error())
	}
	return s.issue(jr, fmt.Sprintf("automatic (provisioning profile %s v%d, step %d)", r.GetProfileId(), r.GetVersion(), i+1), now)
}

// usedTokens remembers consumed step-up nonces until their tokens expire.
type usedTokens struct {
	mu   sync.Mutex
	path string
	seen map[string]int64
}

var errUsed = errors.New("token already used")

func loadUsed(path string) (*usedTokens, error) {
	u := &usedTokens{path: path, seen: map[string]int64{}}
	raw, err := os.ReadFile(path) // #nosec G304 -- configured state file
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &u.seen); err != nil {
			return nil, fmt.Errorf("used-token register corrupt: %w", err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return u, nil
}

func (u *usedTokens) add(nonce string, until, now time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.seen[nonce]; ok {
		return errUsed
	}
	for k, exp := range u.seen {
		if exp < now.Unix() {
			delete(u.seen, k)
		}
	}
	u.seen[nonce] = until.Unix()
	raw, err := json.Marshal(u.seen)
	if err != nil {
		return err
	}
	tmp := u.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		delete(u.seen, nonce)
		return err
	}
	if err := os.Rename(tmp, u.path); err != nil {
		delete(u.seen, nonce)
		return err
	}
	return nil
}

// SignPolicy verifies the operator's approval of a policy document and signs
// it. Policies act on many endpoints for a long time, so they need the Admin
// role; the approval is bound to the exact document bytes.
func (s *Server) SignPolicy(ctx context.Context, req *openrmmv1.SignPolicyRequest) (*openrmmv1.SignPolicyResponse, error) {
	deny := func(reason string, err error) (*openrmmv1.SignPolicyResponse, error) {
		s.log.Warn("policy signature refused", "reason", reason, "err", err, "tenant", req.GetTenantId())
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	raw := req.GetPolicyJson()
	if len(raw) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "policy too large")
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	canon, err := p.Canonical()
	if err != nil || !bytes.Equal(canon, raw) {
		return nil, status.Error(codes.InvalidArgument, "policy document is not canonical")
	}
	if p.TenantID != req.GetTenantId() {
		return nil, status.Error(codes.InvalidArgument, "tenant mismatch")
	}
	claims, v, err := s.verify(ctx, req.GetIdToken())
	if err != nil {
		return deny("operator authentication rejected", err)
	}
	now := s.now()
	if err := v.CheckFresh(claims, now); err != nil {
		return deny("authentication too old", err)
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(policy.AuthNonce(raw))) != 1 {
		return deny("authentication was not issued for this policy", authn.ErrNonce)
	}
	// A policy applies to every computer of the tenant, whatever its OS
	// family, site or group.
	if !v.MayManage(claims, p.TenantID) {
		return deny("operator may not manage this tenant", authn.ErrNoTenant)
	}
	a := v.Access(claims)
	if !a.Super() {
		return deny("only administrators (OpenRMM.Admin) may approve policies", authn.ErrNoRole)
	}
	if err := s.used.add(claims.Nonce, now.Add(2*time.Hour), now); err != nil {
		return deny("authentication already used", err)
	}
	env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: raw,
		Signature: s.signer.Sign(signing.DomainPolicy, raw)})
	if err != nil {
		return nil, status.Error(codes.Internal, "encode envelope")
	}
	op := operatorOf(claims, v)
	s.log.Info("policy signed", "policy", p.ID, "version", p.Version, "name", p.Name, "tenant", p.TenantID,
		"rules", len(p.Rules), "operator", op, "sha256", fmt.Sprintf("%x", sha256.Sum256(raw)))
	return &openrmmv1.SignPolicyResponse{Envelope: env, Operator: op}, nil
}

// SignBaseline signs a tenant's automatic collection policy. No operator
// approves it: the signer accepts only the fixed collections of
// policy.BaselineRules, for a tenant of this console's own directories.
func (s *Server) SignBaseline(_ context.Context, req *openrmmv1.SignBaselineRequest) (*openrmmv1.SignPolicyResponse, error) {
	raw := req.GetPolicyJson()
	if len(raw) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "policy too large")
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	canon, err := p.Canonical()
	if err != nil || !bytes.Equal(canon, raw) {
		return nil, status.Error(codes.InvalidArgument, "policy document is not canonical")
	}
	if p.TenantID != req.GetTenantId() {
		return nil, status.Error(codes.InvalidArgument, "tenant mismatch")
	}
	if !s.ownTenant(p.TenantID) {
		s.log.Warn("automatic collection refused", "reason", "tenant not managed here", "tenant", p.TenantID)
		return nil, status.Error(codes.PermissionDenied, "tenant not managed by this console")
	}
	if err := policy.CheckBaseline(p); err != nil {
		s.log.Warn("automatic collection refused", "reason", err.Error(), "tenant", p.TenantID)
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	env, err := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.signer.KeyID(), Payload: raw,
		Signature: s.signer.Sign(signing.DomainPolicy, raw)})
	if err != nil {
		return nil, status.Error(codes.Internal, "encode envelope")
	}
	s.log.Info("automatic collection signed", "policy", p.ID, "version", p.Version, "tenant", p.TenantID,
		"rules", len(p.Rules), "sha256", fmt.Sprintf("%x", sha256.Sum256(raw)))
	return &openrmmv1.SignPolicyResponse{Envelope: env, Operator: "automatic"}, nil
}

// ownTenant tells whether tenant belongs to this console's own directories
// (not to a central console's operators).
func (s *Server) ownTenant(tenant string) bool {
	for _, ts := range s.verifiers[0].Config().TenantMap {
		for _, t := range ts {
			if t == tenant || t == authn.AllTenants {
				return true
			}
		}
	}
	return false
}

// operatorOf names the operator, marking those of a central console.
func operatorOf(c *authn.Claims, v *authn.Verifier) string {
	if v.Config().MaxRole != "" {
		return c.Operator() + " [central console]"
	}
	return c.Operator()
}

// allowFamily requires min on the computers of the requested OS family: a
// request for any family needs min on both.
func allowFamily(a authn.Access, min, requested string) error {
	fam, ok := a.Family(min)
	if !ok {
		return authn.ErrNoRole
	}
	if fam != "" && requested != fam {
		return fmt.Errorf("%w: the operator's role covers only %s computers, the request is for %q", authn.ErrNoRole, fam, requested)
	}
	return nil
}

// describe names the operator's levels for the signer's log.
func describe(a authn.Access) string {
	if a.Clients == a.Servers {
		return a.Clients
	}
	return "clients:" + a.Clients + " servers:" + a.Servers
}
