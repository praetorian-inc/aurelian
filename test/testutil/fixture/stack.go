//go:build integration

package fixture

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-exec/tfexec"
)

func (f *BaseFixture) loadOutputs(ctx context.Context) error {
	outputs, err := f.ops.Output(ctx)
	if err != nil {
		return fmt.Errorf("terraform output: %w", err)
	}

	f.outputs = outputs
	return nil
}

func (f *BaseFixture) deployStack(ctx context.Context, hash string) error {
	f.t.Log("terraform fixture action: deploy start")
	err := f.ops.Apply(ctx)
	if err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}
	f.t.Log("terraform fixture action: deploy complete")

	err = f.ops.UploadArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("upload fixture artifacts: %w", err)
	}

	err = f.ops.PutRemoteHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("put remote hash: %w", err)
	}

	return nil
}

// teardownStack runs `terraform destroy` using the most authoritative
// source of the module's `.tf` files — the artifacts snapshot in S3 if
// present, otherwise the local fixture directory. After destroy it also
// deletes the artifacts/ prefix so a subsequent Setup uploads fresh.
func (f *BaseFixture) teardownStack(ctx context.Context) error {
	f.t.Log("terraform fixture action: teardown start")

	tmpDir, downloadErr := f.downloadArtifactsToTempDir(ctx)
	if downloadErr != nil {
		f.t.Logf("terraform fixture: failed to download remote artifacts, falling back to local destroy: %v", downloadErr)
		if err := f.ops.Destroy(ctx); err != nil {
			return fmt.Errorf("terraform destroy (fallback): %w", err)
		}
	} else {
		defer os.RemoveAll(tmpDir)

		tmpTf, err := tfexec.NewTerraform(tmpDir, f.cfg.ExecPath)
		if err != nil {
			return fmt.Errorf("create terraform instance for remote artifacts: %w", err)
		}

		if err := tmpTf.Init(ctx, f.cfg.InitOpts...); err != nil {
			return fmt.Errorf("terraform init (remote artifacts): %w", err)
		}

		if err := tmpTf.Destroy(ctx); err != nil {
			return fmt.Errorf("terraform destroy (remote artifacts): %w", err)
		}
	}

	if err := f.ops.DeleteArtifacts(ctx); err != nil {
		return fmt.Errorf("delete fixture artifacts: %w", err)
	}
	f.t.Log("terraform fixture action: teardown complete")

	return nil
}

// redeployStack tears down existing infrastructure and deploys fresh.
// The local directory's init may have been invalidated by the remote
// destroy, so re-init before the deploy.
func (f *BaseFixture) redeployStack(ctx context.Context, hash string) error {
	if err := f.teardownStack(ctx); err != nil {
		return err
	}

	if err := f.ops.Init(ctx, f.cfg.InitOpts...); err != nil {
		return fmt.Errorf("terraform re-init: %w", err)
	}

	return f.deployStack(ctx, hash)
}
