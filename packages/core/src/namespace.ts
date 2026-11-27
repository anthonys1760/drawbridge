const UPSTREAM_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
export const NAMESPACE_SEPARATOR = "__";

export function assertUpstreamName(name: string): void {
  if (!UPSTREAM_NAME.test(name) || name.includes(NAMESPACE_SEPARATOR)) {
    throw new Error(
      `Upstream name "${name}" must match ${UPSTREAM_NAME.source} and must not contain "${NAMESPACE_SEPARATOR}"`,
    );
  }
}

export function namespaceTool(upstream: string, tool: string): string {
  return `${upstream}${NAMESPACE_SEPARATOR}${tool}`;
}

/**
 * Split on the first `__`. Upstream names cannot contain `__`, so a tool
 * whose own name contains `__` still round-trips (`notes__a__b` -> notes / a__b).
 */
export function parseNamespacedTool(
  name: string,
  upstreams: ReadonlySet<string>,
): { upstream: string; tool: string } | undefined {
  const index = name.indexOf(NAMESPACE_SEPARATOR);
  if (index <= 0) return undefined;
  const upstream = name.slice(0, index);
  const tool = name.slice(index + NAMESPACE_SEPARATOR.length);
  if (tool.length === 0 || !upstreams.has(upstream)) return undefined;
  return { upstream, tool };
}
