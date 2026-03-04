import { useEffect, useMemo, useRef, useState } from "react";

function uniqueList(value) {
  if (!Array.isArray(value)) return [];
  const next = [];
  value.forEach((item) => {
    if (typeof item !== "string") return;
    const trimmed = item.trim();
    if (trimmed && !next.includes(trimmed)) {
      next.push(trimmed);
    }
  });
  return next;
}

export default function MultiSelectDropdown({
  label,
  options,
  value,
  onChange,
  placeholder = "Select",
  disabled = false,
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const wrapperRef = useRef(null);
  const normalizedOptions = useMemo(() => uniqueList(options), [options]);
  const selected = useMemo(() => uniqueList(value), [value]);
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return normalizedOptions;
    return normalizedOptions.filter((option) =>
      option.toLowerCase().includes(needle)
    );
  }, [normalizedOptions, search]);

  useEffect(() => {
    if (!open) return;
    const handleClick = (event) => {
      if (!wrapperRef.current) return;
      if (!wrapperRef.current.contains(event.target)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  function toggleOption(option) {
    if (!onChange) return;
    const nextSet = new Set(selected);
    if (nextSet.has(option)) {
      nextSet.delete(option);
    } else {
      nextSet.add(option);
    }
    const next = normalizedOptions.filter((item) => nextSet.has(item));
    onChange(next);
  }

  const display = selected.length
    ? selected.slice(0, 3)
    : [];
  const overflow = selected.length - display.length;

  return (
    <div className={`multi-select ${disabled ? "is-disabled" : ""}`} ref={wrapperRef}>
      {label ? <div className="multi-select-label">{label}</div> : null}
      <button
        type="button"
        className="multi-select-trigger"
        onClick={() => !disabled && setOpen((prev) => !prev)}
        aria-expanded={open}
        disabled={disabled}
      >
        {display.length ? (
          <div className="multi-select-chips">
            {display.map((item) => (
              <span key={item} className="multi-select-chip">
                {item}
              </span>
            ))}
            {overflow > 0 ? (
              <span className="multi-select-chip meta">+{overflow}</span>
            ) : null}
          </div>
        ) : (
          <span className="multi-select-placeholder">{placeholder}</span>
        )}
        <span className="multi-select-caret">▾</span>
      </button>
      {open ? (
        <div className="multi-select-menu">
          <input
            className="multi-select-search"
            type="text"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search groups"
          />
          <div className="multi-select-options">
            {filtered.length ? (
              filtered.map((option) => (
                <label key={option} className="multi-select-option">
                  <input
                    type="checkbox"
                    checked={selectedSet.has(option)}
                    onChange={() => toggleOption(option)}
                  />
                  <span>{option}</span>
                </label>
              ))
            ) : (
              <div className="multi-select-empty">No matches</div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
