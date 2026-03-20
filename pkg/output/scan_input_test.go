package output

import "testing"

func TestScanInputFromGCPResource(t *testing.T) {
	r := GCPResource{
		ResourceID:   "projects/my-proj/zones/us-central1-a/instances/my-vm",
		ResourceType: "compute.googleapis.com/Instance",
		Location:     "us-central1-a",
		ProjectID:    "my-proj",
	}
	content := []byte("SECRET=hunter2")
	label := "startup-script"

	si := ScanInputFromGCPResource(r, label, content)

	if string(si.Content) != "SECRET=hunter2" {
		t.Errorf("Content = %q, want %q", si.Content, "SECRET=hunter2")
	}
	if si.ResourceID != r.ResourceID {
		t.Errorf("ResourceID = %q, want %q", si.ResourceID, r.ResourceID)
	}
	if si.ResourceType != r.ResourceType {
		t.Errorf("ResourceType = %q, want %q", si.ResourceType, r.ResourceType)
	}
	if si.Region != r.Location {
		t.Errorf("Region = %q, want %q", si.Region, r.Location)
	}
	if si.AccountID != r.ProjectID {
		t.Errorf("AccountID = %q, want %q", si.AccountID, r.ProjectID)
	}
	if si.Label != label {
		t.Errorf("Label = %q, want %q", si.Label, label)
	}
}
