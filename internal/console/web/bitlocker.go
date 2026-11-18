package web

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// Viewing a BitLocker recovery key: the console only ever holds the
// ciphertext an agent produced (bitlocker.go in gateway); decrypting one
// needs a fresh MFA approval (like opening a shell) plus the signing
// passphrase (like publishing a module), and is logged on every read, not
// just on the agent's automatic backup.

// bitlockerApprovalTTL is how long an MFA approval waits for the passphrase.
const bitlockerApprovalTTL = 10 * time.Minute

type bitlockerApproval struct {
	AgentID string    `json:"agent_id"`
	Drive   string    `json:"drive"`
	At      time.Time `json:"at"`
}

// handleStartBitlockerView begins the fresh MFA approval for one agent's
// drive.
func (s *Server) handleStartBitlockerView(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id, drive := r.PathValue("id"), r.PathValue("drive")
	back := "/agents/" + id + "?tab=inventory"
	if !ok || !ids.IsUUID(id) || drive == "" {
		http.NotFound(w, r)
		return
	}
	if _, err := s.store.GetAgent(r.Context(), t, id); err != nil {
		s.flash(w, r, s.T(r, "agente non trovato"), back)
		return
	}
	if _, err := s.store.GetBitlockerKey(r.Context(), t, id, drive); err != nil {
		s.flash(w, r, s.T(r, "Nessuna recovery key registrata per questo volume."), back)
		return
	}
	sess := sessionFrom(r.Context())
	p := &Pending{Purpose: "bitlocker", State: ids.NewSecret(24), Nonce: ids.NewSecret(24),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), Return: back,
		BitlockerAgentID: id, BitlockerDrive: drive}
	sess.data.Pending = p
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirectStepUp(w, r, sess, p)
}

// completeBitlockerView records the approval; the passphrase comes next,
// so it never sits in the session.
func (s *Server) completeBitlockerView(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, v *authn.Verifier) {
	op, lang := sess.data.Operator, langOf(r, sess)
	if op == nil || c.ObjectID != op.ObjectID || c.TenantID != op.TenantID || c.Nonce != p.Nonce {
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	if err := v.CheckFresh(c, s.now()); err != nil {
		http.Error(w, tr(lang, "accesso non valido o scaduto: riprova"), http.StatusForbidden)
		return
	}
	sess.data.BitlockerApproval = &bitlockerApproval{AgentID: p.BitlockerAgentID, Drive: p.BitlockerDrive, At: s.now()}
	s.flashTo(w, r, sess, tr(lang, "Approvato: inserisci la passphrase delle chiavi di firma per leggere la chiave."), p.Return)
}

// approvedBitlocker tells whether the session holds a fresh approval for
// exactly this agent and drive.
func (s *Server) approvedBitlocker(sess *session, agentID, drive string) bool {
	a := sess.data.BitlockerApproval
	return a != nil && a.AgentID == agentID && a.Drive == drive && s.now().Sub(a.At) < bitlockerApprovalTTL
}

// consumeBitlocker ends the approval after a decryption attempt: one
// approval, one attempt, successful or not.
func (s *Server) consumeBitlocker(ctx context.Context, w http.ResponseWriter, sess *session) {
	sess.data.BitlockerApproval = nil
	if err := s.save(ctx, w, sess); err != nil {
		s.log.Error("save session", "err", err)
	}
}

type bitlockerViewData struct {
	Agent       store.Agent
	Drive       string
	RecoveryKey string
}

// handleDecryptBitlockerKey decrypts one recovery key through the builder
// and shows it once; the plaintext is never stored or logged, only that it
// was read, by whom and when.
func (s *Server) handleDecryptBitlockerKey(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id, drive := r.PathValue("id"), r.PathValue("drive")
	back := "/agents/" + id + "?tab=inventory"
	if !ok || !ids.IsUUID(id) || drive == "" {
		http.NotFound(w, r)
		return
	}
	sess := sessionFrom(r.Context())
	if !s.approvedBitlocker(sess, id, drive) {
		s.flash(w, r, s.T(r, "Serve una nuova approvazione MFA: riprova."), back)
		return
	}
	pass := r.PostFormValue("passphrase")
	if pass == "" {
		s.flash(w, r, s.T(r, "Passphrase mancante."), back)
		return
	}
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil {
		s.flash(w, r, s.T(r, "agente non trovato"), back)
		return
	}
	k, err := s.store.GetBitlockerKey(r.Context(), t, id, drive)
	if err != nil {
		s.consumeBitlocker(r.Context(), w, sess)
		s.flash(w, r, s.T(r, "Nessuna recovery key registrata per questo volume."), back)
		return
	}
	if s.builder == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	resp, err := s.builder.DecryptBitlockerKey(ctx, &openrmmv1.DecryptBitlockerKeyRequest{Ciphertext: k.Ciphertext, Passphrase: pass})
	if err != nil {
		s.flash(w, r, s.Tf(r, "Operazione non riuscita: %s", grpcMessage(err)), back)
		return
	}
	s.consumeBitlocker(r.Context(), w, sess)
	s.audit(r.Context(), t, sess.data.Operator, "bitlocker.key.viewed", id, map[string]any{"drive": drive})
	s.render(w, r, "bitlockerkey", s.Tf(r, "Recovery key di %s", drive), bitlockerViewData{Agent: a, Drive: drive, RecoveryKey: resp.GetRecoveryKey()})
}
