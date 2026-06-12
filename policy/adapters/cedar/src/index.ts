/**
 * AWS Cedar policy adapter for Ovara.
 *
 * Translates Cedar policies to Ovara's native policy JSON format.
 *
 * Cedar → Ovara mapping:
 *
 *   permit(...)   → rule.allow = true
 *   forbid(...)   → rule.deny = true
 *   no explicit permit → rule.escalate = true (default-deny)
 *
 *   action == Action::"shell"  → rule.action_type = "shell"
 *   resource == Repo::"acme/*" → rule.environment / conditions
 *   principal == User::"..."   → rule.conditions.principal
 *
 * Example input Cedar:
 *
 *   permit (
 *     principal == Agent::"agt-001",
 *     action == Action::"git.pull",
 *     resource == Repo::"*"
 *   );
 *
 *   forbid (
 *     principal,
 *     action == Action::"shell",
 *     resource == Repo::"acme/api"
 *   ) when { principal.trust_score < 0.5 };
 */

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

export interface CedarPolicy {
  statements: CedarStatement[];
}

export interface CedarStatement {
  effect: 'permit' | 'forbid';
  principal?: CedarPrincipal;
  action: CedarAction;
  resource?: CedarResource;
  conditions?: CedarCondition[];
  line: number;
  raw: string;
}

export interface CedarPrincipal {
  type?: string; // e.g. "Agent"
  id?: string;   // e.g. "agt-001" or "*"
}

export interface CedarAction {
  type?: string; // e.g. "Action"
  id: string;    // e.g. "shell" or "*"
}

export interface CedarResource {
  type?: string; // e.g. "Repo"
  id?: string;   // e.g. "acme/api" or "*"
}

export interface CedarCondition {
  key: string;
  op: '<' | '<=' | '==' | '!=' | '>=' | '>';
  value: string | number | boolean;
}

/**
 * Parse a Cedar policy source string into structured statements.
 *
 * Supports the subset of Cedar used for Ovara: permit/forbid with
 * principal/action/resource clauses and simple when conditions.
 */
export function parseCedar(source: string): CedarPolicy {
  const statements: CedarStatement[] = [];
  const errors: string[] = [];

  // Find each statement: permit(...) or forbid(...);
  const stmtRegex = /(permit|forbid)\s*\(([\s\S]*?)\)\s*(?:when\s*\{([\s\S]*?)\})?\s*;/g;
  let m: RegExpExecArray | null;
  while ((m = stmtRegex.exec(source)) !== null) {
    const effect = m[1] as 'permit' | 'forbid';
    const body = m[2];
    const whenBody = m[3];
    const stmt: CedarStatement = {
      effect,
      action: { id: '*' },
      line: lineAt(source, m.index),
      raw: m[0],
    };

    // Split the body into clauses separated by commas at the top level
    const clauses = splitTopLevel(body, ',');
    for (const clause of clauses) {
      const trimmed = clause.trim();
      if (!trimmed) continue;

      // Bare principal (matches any principal)
      if (trimmed === 'principal' || trimmed.startsWith('principal,')) {
        stmt.principal = { id: '*' };
        continue;
      }
      // Bare action
      if (trimmed === 'action' || trimmed === 'action,') {
        stmt.action = { id: '*' };
        continue;
      }
      // Bare resource
      if (trimmed === 'resource' || trimmed === 'resource,') {
        stmt.resource = { id: '*' };
        continue;
      }

      const principalMatch = trimmed.match(/^principal\s*(==|!=)\s*([\w:]+?)(?:::"([^"]*)"|\s*==\s*"([^"]*)")?$/);
      if (principalMatch && trimmed.startsWith('principal')) {
        const [, , type, id1, id2] = principalMatch;
        stmt.principal = { type, id: id1 ?? id2 ?? '*' };
        continue;
      }

      const actionMatch = trimmed.match(/^action\s*(==|!=)\s*([\w]+?)(?:::"([^"]*)"|\s*==\s*"([^"]*)")?$/);
      if (actionMatch && trimmed.startsWith('action')) {
        const [, , type, id1, id2] = actionMatch;
        stmt.action = { type, id: id1 ?? id2 ?? '*' };
        continue;
      }

      const resourceMatch = trimmed.match(/^resource\s*(==|!=)\s*([\w]+?)(?:::"([^"]*)"|\s*==\s*"([^"]*)")?$/);
      if (resourceMatch && trimmed.startsWith('resource')) {
        const [, , type, id1, id2] = resourceMatch;
        stmt.resource = { type, id: id1 ?? id2 ?? '*' };
        continue;
      }

      errors.push(`unrecognized clause: ${trimmed}`);
    }

    if (whenBody) {
      stmt.conditions = parseWhenBody(whenBody);
    }

    statements.push(stmt);
  }

  if (errors.length > 0) {
    throw new Error(`[cedar-adapter:parse] ${errors[0]}`);
  }

  return { statements };
}

function splitTopLevel(body: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let inString = false;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '"' && body[i - 1] !== '\\') inString = !inString;
    if (!inString) {
      if (c === '(' || c === '[') depth++;
      if (c === ')' || c === ']') depth--;
      if (c === sep && depth === 0) {
        parts.push(body.slice(start, i));
        start = i + 1;
      }
    }
  }
  parts.push(body.slice(start));
  return parts;
}

function parseWhenBody(body: string): CedarCondition[] {
  const conditions: CedarCondition[] = [];
  // Split by comma or semicolon (Cedar allows both in when blocks)
  const parts = splitTopLevel(body.replace(/[;\n]/g, ','), ',');
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    // Match: principal.trust_score < 0.5
    const m = trimmed.match(/^(\w+(?:\.\w+)*)\s*([<>=!]+)\s*(.+)$/);
    if (!m) continue;
    const [, key, op, rawVal] = m;
    let value: string | number | boolean = rawVal.trim();
    // Try to parse as number
    const num = Number(value);
    if (!isNaN(num) && value !== '' && /^-?\d+(\.\d+)?$/.test(String(value))) {
      value = num;
    } else if (value === 'true' || value === 'false') {
      value = value === 'true';
    } else if (typeof value === 'string' && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    conditions.push({ key, op: op as CedarCondition['op'], value });
  }
  return conditions;
}

function lineAt(source: string, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

function mapStatement(stmt: CedarStatement): OvaraRule {
  const rule: OvaraRule = {
    action_type: stmt.action.id,
    environment: stmt.resource?.id ?? '*',
  };

  if (stmt.principal?.id && stmt.principal.id !== '*') {
    rule.conditions = { ...rule.conditions, principal_id: stmt.principal.id };
  }

  if (stmt.conditions && stmt.conditions.length > 0) {
    const condObj: Record<string, unknown> = { ...rule.conditions };
    for (const c of stmt.conditions) {
      // Encode operator into key, e.g. "trust_score_lt" for trust_score < X
      const opSuffix: Record<string, string> = {
        '<': 'lt', '<=': 'lte', '==': 'eq', '!=': 'ne', '>=': 'gte', '>': 'gt',
      };
      const suffix = opSuffix[c.op] ?? c.op;
      // Replace dots with underscores so keys are JSON-friendly
      const safeKey = c.key.replace(/\./g, '_');
      condObj[`${safeKey}_${suffix}`] = c.value;
    }
    rule.conditions = condObj;
  }

  if (stmt.effect === 'permit') {
    rule.allow = true;
  } else {
    rule.deny = true;
  }

  rule.description = `Translated from Cedar ${stmt.effect} at line ${stmt.line}`;
  return rule;
}

/**
 * Translate a Cedar policy to an Ovara policy.
 */
export function translateCedar(cedar: string): OvaraPolicy {
  if (!cedar.trim()) {
    throw new Error('[cedar-adapter:parse] empty policy');
  }
  const { statements } = parseCedar(cedar);
  if (statements.length === 0) {
    throw new Error('[cedar-adapter:semantic] no statements found');
  }

  const hasPermit = statements.some(s => s.effect === 'permit');
  const rules = statements.map(mapStatement);

  if (!hasPermit) {
    rules.push({
      action_type: '*',
      environment: '*',
      escalate: true,
      description: 'Cedar policy has no permit statements → catch-all escalate',
    });
  }

  return {
    version: 'v1-from-cedar',
    rules,
  };
}

export function translateCedarJSON(cedar: string): string {
  return JSON.stringify(translateCedar(cedar), null, 2);
}
