/** Small shared formatters. */

export function timeOnly(iso: string | null | undefined): string {
  if (!iso) return "--:--:--";
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function duration(fromIso: string, toIso: string): string {
  const seconds = Math.max(0, (new Date(toIso).getTime() - new Date(fromIso).getTime()) / 1000);
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function relativeSeconds(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function percent(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

/** The normalizer stores its human-readable reasons as "finding:..." tags. */
export function findings(tags: string[]): string[] {
  return tags.filter((t) => t.startsWith("finding:")).map((t) => t.slice("finding:".length));
}

export function plainTags(tags: string[]): string[] {
  return tags.filter((t) => !t.startsWith("finding:"));
}

export function titleCase(value: string): string {
  return value
    .toLowerCase()
    .split(/[_\s]+/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
