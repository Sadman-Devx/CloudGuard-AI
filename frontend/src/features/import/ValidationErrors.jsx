import Notice from "../../components/Notice.jsx";

/** Renders an ApiError: a per-field list for 422 validation failures, a plain message otherwise. */
export default function ValidationErrors({ error }) {
  const issues = Array.isArray(error.details) ? error.details : [];
  const isValidation = error.code === "invalid_configuration" && issues.length > 0;

  return (
    <Notice
      tone="error"
      title={isValidation ? `Configuration rejected: ${issues.length} problem(s). Nothing was saved.` : error.message}
    >
      {isValidation && (
        <ul className="mt-1 space-y-1">
          {issues.map((issue, index) => (
            <li key={`${issue.path}-${issue.code}-${index}`} className="text-sm">
              <code className="rounded bg-rose-100 px-1 text-xs">{issue.path || "(root)"}</code>{" "}
              <span className="font-medium">{issue.code}</span>: {issue.message}
            </li>
          ))}
        </ul>
      )}
      {error.requestId && <p className="mt-2 text-xs opacity-70">Request ID: {error.requestId}</p>}
    </Notice>
  );
}
