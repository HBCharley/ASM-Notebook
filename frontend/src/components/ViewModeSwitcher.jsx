import React, { useMemo } from "react";
import { Activity, BarChart3, LayoutGrid } from "lucide-react";

const MODES = [
  { key: "standard", label: "Standard", icon: LayoutGrid },
  { key: "executive", label: "Executive", icon: BarChart3 },
  { key: "soc", label: "SOC", icon: Activity },
];

export default function ViewModeSwitcher({ value = "standard", onChange }) {
  const index = useMemo(
    () => Math.max(0, MODES.findIndex((mode) => mode.key === value)),
    [value]
  );
  return (
    <div className="view-switcher" role="radiogroup" aria-label="View mode">
      <div
        className="view-switcher-pill"
        style={{ transform: `translateX(${index * 52}px)` }}
      />
      {MODES.map((mode) => {
        const Icon = mode.icon;
        const active = mode.key === value;
        return (
          <button
            key={mode.key}
            type="button"
            className={`view-switcher-btn ${active ? "active" : ""}`}
            onClick={() => onChange?.(mode.key)}
            aria-label={mode.label}
            aria-pressed={active}
          >
            <Icon size={18} />
          </button>
        );
      })}
    </div>
  );
}
