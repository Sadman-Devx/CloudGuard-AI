const TONES = {
  info: "border-sky-200 bg-sky-50 text-sky-900",
  success: "border-emerald-200 bg-emerald-50 text-emerald-900",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  error: "border-rose-200 bg-rose-50 text-rose-900",
};

export default function Notice({ tone = "info", title, children, role }) {
  return (
    <div
      role={role ?? (tone === "error" ? "alert" : "status")}
      className={`rounded-lg border px-4 py-3 text-sm ${TONES[tone]}`}
    >
      {title && <p className="font-semibold">{title}</p>}
      {children && <div className={title ? "mt-1" : ""}>{children}</div>}
    </div>
  );
}
