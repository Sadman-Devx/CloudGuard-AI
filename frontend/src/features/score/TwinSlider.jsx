import { useState } from "react";

import SeverityBadge from "../findings/SeverityBadge.jsx";
import ScoreGauge from "./ScoreGauge.jsx";

// Grades are decided by the backend; the slider only picks which side to show once it passes halfway.
const HALFWAY = 50;

function FindingRow({ finding, tag }) {
  return (
    <li className="flex flex-wrap items-center gap-2 text-sm text-slate-800">
      <SeverityBadge severity={finding.severity} />
      <span>
        {finding.rule_id} · {finding.resource_id} — {finding.title}
      </span>
      {tag && <span className="text-[11px] font-semibold text-slate-500">{tag}</span>}
    </li>
  );
}

/**
 * Before / after slider for a simulated change.
 *
 * `score` is the backend object { before, after, delta }; `findings` is the simulation diff
 * { resolved, remaining, introduced }. Dragging from 0 to 100 moves the displayed score from the
 * "before" value to the "after" value, and switches the list from the current findings
 * (resolved + remaining) to the findings after the change (remaining + introduced).
 */
export default function TwinSlider({ score, findings }) {
  const [position, setPosition] = useState(0);
  if (!score?.before || !score?.after) return null;

  const showAfter = position >= HALFWAY;
  const side = showAfter ? score.after : score.before;
  const shown = Math.round(score.before.value + (score.after.value - score.before.value) * (position / 100));

  const resolved = findings?.resolved ?? [];
  const remaining = findings?.remaining ?? [];
  const introduced = findings?.introduced ?? [];
  const rows = showAfter
    ? [
        ...remaining.map((f) => ({ f, tag: "still open" })),
        ...introduced.map((f) => ({ f, tag: "new" })),
      ]
    : [
        ...resolved.map((f) => ({ f, tag: "fixed by this change" })),
        ...remaining.map((f) => ({ f, tag: "" })),
      ];

  const deltaText =
    score.delta > 0
      ? `+${score.delta} points safer`
      : score.delta < 0
        ? `${score.delta} points riskier`
        : "No change in score";

  return (
    <section aria-label="Before and after twin" className="space-y-3">
      <div className="flex flex-wrap items-center gap-4">
        <ScoreGauge
          value={shown}
          grade={showAfter ? score.after.grade : score.before.grade}
          max={side.max}
          label={showAfter ? "Score after the change" : "Score before the change"}
        />
        <div className="space-y-1">
          <p className="text-sm font-semibold text-slate-900">
            {score.before.value} → {score.after.value} ({deltaText})
          </p>
          <p className="text-xs text-slate-500">
            Showing the network {showAfter ? "after" : "before"} the change.
          </p>
        </div>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between text-xs font-medium text-slate-600">
          <button
            type="button"
            onClick={() => setPosition(0)}
            aria-pressed={!showAfter}
            className="underline-offset-2 hover:underline"
          >
            Before
          </button>
          <button
            type="button"
            onClick={() => setPosition(100)}
            aria-pressed={showAfter}
            className="underline-offset-2 hover:underline"
          >
            After
          </button>
        </div>
        <input
          type="range"
          min={0}
          max={100}
          step={1}
          value={position}
          onChange={(e) => setPosition(Number(e.target.value))}
          aria-label="Before and after slider"
          aria-valuetext={showAfter ? "After the change" : "Before the change"}
          className="w-full"
        />
      </div>

      {rows.length === 0 ? (
        <p className="text-sm text-slate-600">No findings on this side.</p>
      ) : (
        <ul aria-label={showAfter ? "Findings after" : "Findings before"} className="space-y-1">
          {rows.map(({ f, tag }) => (
            <FindingRow key={`${tag}-${f.rule_id}-${f.resource_id}`} finding={f} tag={tag} />
          ))}
        </ul>
      )}

      <p className="text-[11px] text-slate-500">
        The score is 100 minus a fixed penalty per finding (critical 25, high 15, medium 8, low 3,
        info 1). It only counts the modelled rules, so 100 does not prove the network is secure.
      </p>
    </section>
  );
}