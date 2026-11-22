import { scoreColor } from "./colors.js";

/** Circular gauge of a 0-100 score with its grade in the middle. */
export default function ScoreRing({ value, grade, size = 96 }) {
  const stroke = Math.max(8, Math.round(size / 9));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const filled = (Math.max(0, Math.min(100, value)) / 100) * circumference;
  return (
    <svg
      role="img"
      aria-label={`Score ${value} out of 100, grade ${grade}`}
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
    >
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#e2e8f0" strokeWidth={stroke} />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={scoreColor(value)}
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference - filled}`}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x="50%" y="47%" textAnchor="middle" fontSize={size / 3.2} fontWeight="700" fill="#0f172a">
        {value}
      </text>
      <text x="50%" y="68%" textAnchor="middle" fontSize={size / 7} fill="#64748b">
        grade {grade}
      </text>
    </svg>
  );
}
