package provisioning

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Document{Steps: []Step{
		{Type: StepWorkflow, WorkflowID: "0b8f5a4e-7f0e-4c1e-9d5c-1f2a3b4c5d6e", Revision: 2, Name: "7-Zip"},
		{Type: StepReboot},
	}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Document{
		"empty":            {},
		"no workflow":      {Steps: []Step{{Type: StepWorkflow}}},
		"reboot with wf":   {Steps: []Step{{Type: StepReboot, WorkflowID: "0b8f5a4e-7f0e-4c1e-9d5c-1f2a3b4c5d6e", Revision: 1}}},
		"unknown type":     {Steps: []Step{{Type: "format"}}},
		"name with return": {Steps: []Step{{Type: StepReboot, Name: "a\nb"}}},
		"name too long":    {Steps: []Step{{Type: StepReboot, Name: strings.Repeat("x", MaxStepName+1)}}},
	}
	for name, d := range bad {
		if d.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRebootParamsAreJSON(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(RebootParams, &m); err != nil || m["only_if_pending"] != false {
		t.Fatalf("reboot params: %v %v", m, err)
	}
}
