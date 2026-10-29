import { useRef, useState } from "react";

export const MAX_FILE_BYTES = 1_000_000;

export default function ImportForm({ fixtures, disabled, busy, onImportFixture, onUploadFile }) {
  const [fixture, setFixture] = useState("");
  const [fileError, setFileError] = useState(null);
  const fileInput = useRef(null);

  const upload = async (event) => {
    event.preventDefault();
    setFileError(null);
    const file = fileInput.current?.files?.[0];
    if (!file) {
      setFileError("Choose a .json file first.");
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setFileError(`File is too large (limit ${MAX_FILE_BYTES / 1_000_000} MB).`);
      return;
    }
    let config;
    try {
      config = JSON.parse(await file.text());
    } catch (error) {
      setFileError(`This file is not valid JSON: ${error.message}`);
      return;
    }
    onUploadFile(config, file.name);
  };

  return (
    <div className="space-y-6">
      <div>
        <label htmlFor="fixture-select" className="block text-sm font-medium text-slate-700">
          Sample configuration
        </label>
        <div className="mt-1 flex gap-2">
          <select
            id="fixture-select"
            value={fixture}
            onChange={(e) => setFixture(e.target.value)}
            className="min-w-0 flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
          >
            <option value="">Select a fixture…</option>
            {fixtures.map((f) => (
              <option key={f.name} value={f.name}>
                {f.title}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={disabled || busy || !fixture}
            onClick={() => onImportFixture(fixture)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            Import sample
          </button>
        </div>
      </div>

      <form onSubmit={upload}>
        <label htmlFor="config-file" className="block text-sm font-medium text-slate-700">
          Or upload a configuration (.json)
        </label>
        <div className="mt-1 flex gap-2">
          <input
            id="config-file"
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            className="min-w-0 flex-1 text-sm file:mr-3 file:rounded-lg file:border-0 file:bg-slate-100 file:px-3 file:py-2 file:text-sm file:font-medium"
          />
          <button
            type="submit"
            disabled={disabled || busy}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            Upload
          </button>
        </div>
        {fileError && (
          <p role="alert" className="mt-2 text-sm text-rose-700">
            {fileError}
          </p>
        )}
      </form>
    </div>
  );
}
