// Package provisioning describes provisioning profiles: the ordered steps
// run on a freshly installed computer (workflows that install software and
// run scripts, reboots). The console runs a profile one step at a time,
// dispatching the next step when the agent reports the previous one; the
// agent only ever sees ordinary signed jobs.
//
// A profile version is a Document. An administrator approves it once with
// MFA (internal/console/profilereq); the signer then signs the job of each
// step on the computers the console names.
package provisioning

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

const (
	MaxSteps    = 30
	MaxStepName = 128
)

// Step types.
const (
	StepWorkflow = "workflow" // a pinned revision of a software distribution workflow
	StepReboot   = "reboot"   // reboot, then wait for the agent to reconnect
)

// StepTypes lists the types in the editor's order.
var StepTypes = []string{StepWorkflow, StepReboot}

// RebootModule and RebootAction run a reboot step. RebootParams reboots at
// once whatever the reboot policy says: a new computer has no user to
// warn. The minute of notice lets the agent report the job before going
// down.
const (
	RebootModule = "reboot"
	RebootAction = "reboot"
)

var RebootParams = []byte(`{"min_battery_percent":0,"min_pending_hours":0,"notice_minutes":1,"only_if_pending":false,"skip_if_user":false}`)

// Document is a profile version.
type Document struct {
	Steps []Step `json:"steps"`
}

// Step is an action of the profile.
type Step struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type"`
	// workflow: the workflow and the revision pinned when the profile was
	// saved.
	WorkflowID string `json:"workflow_id,omitempty"`
	Revision   int    `json:"revision,omitempty"`
	// ContinueOnError: a failure is recorded and the next step runs.
	ContinueOnError bool `json:"continue_on_error,omitempty"`
}

// Parse decodes and validates a document.
func Parse(raw []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks the document.
func (d Document) Validate() error {
	if n := len(d.Steps); n == 0 || n > MaxSteps {
		return fmt.Errorf("a profile has between 1 and %d steps", MaxSteps)
	}
	for i, s := range d.Steps {
		if err := s.validate(); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
	}
	return nil
}

func (s Step) validate() error {
	if utf8.RuneCountInString(s.Name) > MaxStepName || strings.ContainsAny(s.Name, "\r\n") {
		return errors.New("name too long")
	}
	switch s.Type {
	case StepWorkflow:
		if !ids.IsUUID(s.WorkflowID) || s.Revision < 1 {
			return errors.New("choose a workflow")
		}
	case StepReboot:
		if s.WorkflowID != "" || s.Revision != 0 {
			return errors.New("a reboot takes no workflow")
		}
	default:
		return fmt.Errorf("unknown step type %q", s.Type)
	}
	return nil
}
