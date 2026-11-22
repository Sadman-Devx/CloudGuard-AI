import { useRef, useState } from "react";

export const MAX_IAC_BYTES = 2_000_000;

const FORMATS = {
  terraform: {
    label: "Terraform (terraform show -json)",
    accept: ".json,application/json",
    hint: "Run `terraform plan -out tf.plan` then `terraform show -json tf.plan > plan.json` (a state file works too).",
  },
  cloudformation: {
    label: "CloudFormation template",
    accept: ".json,.yaml,.yml,.template,.txt",
    hint: "A template in JSON or YAML. Short-form functions such as !Ref are understood; nothing is deployed.",
  },
};

/** Upload or paste an infrastructure-as-code file. It is parsed on the server, never executed. */
export default function IacImportForm({ disabled, busy, onImport }) {
  const [format, setFormat] = useState("terraform");
  const [text, setText] = useState("");
  const [fileName, setFileName] = useState("");
  const [fileError, setFileError] = useState(null);
  const fileInput = useRef(null);

  const readFile = async (event) => {
    setFileError(null);
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_IAC_BYTES) {
      setFileError(`File is too large (limit ${MAX_IAC_BYTES / 1_000_000} MB).`);
      return;
    }
    setText(await file.text());
    setFileName(file.name);
  };

  const submit = (event) => {
    event.preventDefault();
    setFileError(null);
    if (!text.trim()) {
      setFileError("Choose a file or paste its content first.");
      return;
    }
    onImport({ format, content: text, name: fileName });
  };

  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Import infrastructure as code">
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">Format</span>
        <select
          value={format}
          onChange={(e) => setFormat(e.target.value)}
          className="mt-0.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm"
        >
          {Object.entries(FORMATS).map(([id, f]) => (
            <option key={id} value={id}>
              {f.label}
            </option>
          ))}
        </select>
      </label>
      <p className="text-xs text-slate-500">{FORMATS[format].hint}</p>
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">File</span>
        <input
          ref={fileInput}
          type="file"
          accept={FORMATS[format].accept}
          onChange={readFile}
          className="mt-0.5 block w-full text-sm"
        />
      </label>
      <label className="block text-sm">
        <span className="block text-xs font-medium text-slate-500">
          …or paste the content
        </span>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={6}
          spellCheck={false}
          className="mt-0.5 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
        />
      </label>
      {fileError && (
        <p role="alert" className="text-sm text-red-700">
          {fileError}
        </p>
      )}
      <button
        type="submit"
        disabled={disabled || busy}
        className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
      >
        Analyse this file
      </button>
    </form>
  );
}
