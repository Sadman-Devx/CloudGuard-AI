import { SEVERITY_STYLES } from "./severity.js";

export default function SeverityBadge({ severity }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
      }`}
    >
      {severity}
    </span>
  );
}