import { useState } from "react";

import { getAwsImportStatus } from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";
import { useAsyncData } from "../../hooks/useAsyncData.js";

const VPC_ID = /^vpc-[0-9a-f]{8,17}$/;

/**
 * Live, read-only import. The server uses its own AWS identity (optionally assuming a read-only
 * role); no credentials are typed here or sent over the API.
 */
export default function AwsImportForm({ disabled, busy, onImport }) {
  const status = useAsyncData("aws-status", getAwsImportStatus);
  const [region, setRegion] = useState("us-east-1");
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState("");
  const [vpcs, setVpcs] = useState("");
  const [includeS3, setIncludeS3] = useState(false);
  const [problem, setProblem] = useState(null);

  if (status.error) {
    return (
      <Notice tone="error" title="Could not check live import">
        {status.error.message}
      </Notice>
    );
  }
  if (!status.data) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Checking whether live import is available…
      </p>
    );
  }
  if (!status.data.enabled) {
    return (
      <Notice tone="info" title="Live AWS import is turned off on this server">
        It needs the backend to run with <code>AWS_IMPORT_ENABLED=true</code>,
        AWS credentials of its own, and ideally a read-only role (see{" "}
        <code>infra/aws-readonly-role.yaml</code>). It is off by default because
        the API has no sign-in yet.
      </Notice>
    );
  }

  const submit = (event) => {
    event.preventDefault();
    setProblem(null);
    const vpc_ids = vpcs
      .split(/[\s,]+/)
      .map((v) => v.trim())
      .filter(Boolean);
    if (vpc_ids.some((v) => !VPC_ID.test(v))) {
      setProblem("VPC ids look like vpc-0a1b2c3d4e5f67890.");
      return;
    }
    onImport({
      region: region.trim(),
      ...(roleArn.trim() ? { role_arn: roleArn.trim() } : {}),
      ...(externalId.trim() ? { external_id: externalId.trim() } : {}),
      ...(vpc_ids.length ? { vpc_ids } : {}),
      include_s3: includeS3,
    });
  };

  const field =
    "mt-0.5 w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm";
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Import from AWS">
      <p className="text-xs text-slate-500">
        Read-only: only Describe/List/Get calls are made, nothing is created,
        changed or deleted. No credentials are entered here.
      </p>
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">Region</span>
        <input
          required
          value={region}
          onChange={(e) => setRegion(e.target.value)}
          className={field}
          placeholder="us-east-1"
        />
      </label>
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">
          Role to assume {status.data.role_allowlist ? "(required)" : "(optional)"}
        </span>
        <input
          value={roleArn}
          onChange={(e) => setRoleArn(e.target.value)}
          required={status.data.role_allowlist}
          className={field}
          placeholder="arn:aws:iam::123456789012:role/CloudGuardReadOnly"
        />
      </label>
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">
          External ID (optional)
        </span>
        <input
          value={externalId}
          onChange={(e) => setExternalId(e.target.value)}
          className={field}
        />
      </label>
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">
          Only these VPCs (optional, comma separated)
        </span>
        <input
          value={vpcs}
          onChange={(e) => setVpcs(e.target.value)}
          className={field}
          placeholder="vpc-0a1b2c3d4e5f67890"
        />
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={includeS3}
          onChange={(e) => setIncludeS3(e.target.checked)}
        />
        Also check S3 bucket public access
      </label>
      {problem && (
        <p role="alert" className="text-sm text-red-700">
          {problem}
        </p>
      )}
      <button
        type="submit"
        disabled={disabled || busy}
        className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
      >
        Import from AWS (read-only)
      </button>
    </form>
  );
}
