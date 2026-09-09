import React, { useId } from 'react';
import { formatYears } from '../format';

interface RangeSliderProps {
  label: string;
  value: number;
  min?: number;
  max?: number;
  step?: number | 'any';
  unit?: string;
  onChange: (value: number) => void;
  className?: string;
  description?: string;
}

export const RangeSlider: React.FC<RangeSliderProps> = ({
  label,
  value,
  min = 3,
  max = 20,
  step = 1,
  unit = 'yrs',
  onChange,
  className = '',
  description,
}) => {
  const inputId = useId();
  const percentage = Math.min(Math.max(((value - min) / (max - min)) * 100, 0), 100);

  return (
    <div className={`w-full max-w-[420px] ${className}`}>
      <div className="flex justify-between gap-3 text-[12.5px] text-ink-soft mb-2">
        <label htmlFor={inputId}>{label}</label>
        <b className="text-ink font-mono font-semibold whitespace-nowrap">
          {formatYears(value)} {unit}
        </b>
      </div>
      <input
        id={inputId}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        aria-valuetext={`${formatYears(value)} ${unit}`}
        aria-describedby={description ? `${inputId}-description` : undefined}
        onChange={(e) => onChange(Number(Number(e.target.value).toFixed(2)))}
        className="ecdat-slider cursor-pointer"
        style={{
          background: `linear-gradient(90deg, var(--qubit, #0E9C90) ${percentage}%, var(--border-strong, #C7CDD3) ${percentage}%)`,
        }}
      />
      {description && <p id={`${inputId}-description`} className="text-xs text-ink-soft mt-3 leading-relaxed">{description}</p>}
    </div>
  );
};
