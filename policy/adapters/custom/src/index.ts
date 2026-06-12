/**
 * Custom JSON policy adapter for Ovara.
 *
 * Accepts a JSON array of "mappings" that translate fields from an
 * external system into Ovara's policy model. This is the fallback
 * for systems that don't fit OPA or Cedar.
 *
 * Example mapping:
 *
 * {
 *   "version": "v1",
 *   "mappings": [
 *     {
 *       "name": "from-external-system",
 *       "source": "external",
 *       "match": {
 *         "action": "$.operation",
 *         "resource": "$.target",
 *         "effect": "$.outcome"
 *       },
 *       "rules": [...]
 *     }
 *   ]
 * }
 */

export interface CustomMapping {
  name: string;
  source: string;
  match: {
    action: string;   // JSONPath or "field" reference
    resource: string;
    effect: string;
  };
  rules: ExternalRule[];
}

export interface ExternalRule {
  action: string;
  resource?: string;
  effect: 'allow' | 'deny' | 'escalate';
  conditions?: Record<string, unknown>;
  description?: string;
}

export interface CustomAdapterConfig {
  version: string;
  mappings: CustomMapping[];
}

export interface OvaraRule {
  action_type: string;
  environment: string;
  allow?: boolean;
  deny?: boolean;
  escalate?: boolean;
  conditions?: Record<string, unknown>;
  description?: string;
}

export interface OvaraPolicy {
  version: string;
  rules: OvaraRule[];
}

/**
 * Resolve a simple JSONPath-like reference against an object.
 * Supports $.field, $.field.subfield, and literal "$" (whole object).
 */
function resolvePath(path: string, obj: unknown): unknown {
  if (path === '$') return obj;
  if (!path.startsWith('$.')) return undefined;
  const parts = path.slice(2).split('.');
  let current: any = obj;
  for (const part of parts) {
    if (current == null) return undefined;
    current = current[part];
  }
  return current;
}

function mapRule(external: ExternalRule, mapping: CustomMapping, source: unknown): OvaraRule {
  // Resolve the action/resource from the source using the mapping
  const actionVal = resolvePath(mapping.match.action, source);
  const resourceVal = mapping.match.resource
    ? resolvePath(mapping.match.resource, source)
    : '*';

  return {
    action_type: actionVal !== undefined ? String(actionVal) : external.action,
    environment: resourceVal !== undefined ? String(resourceVal) : (external.resource ?? '*'),
    [external.effect]: true,
    conditions: external.conditions,
    description: external.description ?? `Translated from ${mapping.name}`,
  };
}

/**
 * Translate a CustomAdapterConfig to an Ovara policy.
 *
 * If `sources` is provided, each source object is matched against the
 * mappings and contributes rules. Otherwise, the rules embedded in the
 * mapping are used directly.
 */
export function translateCustom(
  config: CustomAdapterConfig,
  sources?: unknown[]
): OvaraPolicy {
  if (!config.version) {
    throw new Error('[custom-adapter:semantic] missing version in config');
  }
  if (!Array.isArray(config.mappings) || config.mappings.length === 0) {
    throw new Error('[custom-adapter:semantic] no mappings provided');
  }

  const rules: OvaraRule[] = [];

  for (const mapping of config.mappings) {
    if (!mapping.name) {
      throw new Error('[custom-adapter:semantic] mapping missing name');
    }

    if (sources && sources.length > 0) {
      // For each source, produce a rule based on the mapping
      for (const source of sources) {
        if (mapping.rules.length > 0) {
          // Apply each template rule with the resolved fields
          for (const tpl of mapping.rules) {
            rules.push(mapRule(tpl, mapping, source));
          }
        } else {
          // No templates — just emit a wildcard based on effect
          const effectVal = resolvePath(mapping.match.effect, source);
          rules.push({
            action_type: '*',
            environment: '*',
            [effectVal === 'allow' ? 'allow' : effectVal === 'deny' ? 'deny' : 'escalate']: true,
            description: `Translated from ${mapping.name}`,
          });
        }
      }
    } else {
      // No sources — emit the template rules directly
      for (const tpl of mapping.rules) {
        rules.push({
          action_type: tpl.action,
          environment: tpl.resource ?? '*',
          [tpl.effect]: true,
          conditions: tpl.conditions,
          description: tpl.description ?? `From ${mapping.name}`,
        });
      }
    }
  }

  return {
    version: `v1-from-custom-${config.version}`,
    rules,
  };
}

export function translateCustomJSON(config: CustomAdapterConfig, sources?: unknown[]): string {
  return JSON.stringify(translateCustom(config, sources), null, 2);
}
