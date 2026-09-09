const yearFormatter = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2, useGrouping: false });

export const formatYears = (years: number): string => yearFormatter.format(years);
export const targetName = (target: string): string => target.replace(/\\/g, '/').split('/').filter(Boolean).pop() || target;
