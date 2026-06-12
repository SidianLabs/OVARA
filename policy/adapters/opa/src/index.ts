/**
 * OPA (Rego) policy adapter for Ovara.
 *
 * Translates Open Policy Agent Rego policies to Ovara's native policy JSON
 * format. Rego's `allow`/`deny` decisions are mapped to Ovara's
 * `allow`/`deny`/`escalate` outcomes.
 *
 * Rego → Ovara mapping:
 *
 *   allow  := true   → rule.allow = true
 *   deny   := true   → rule.deny = true
 *   both false / undefined → rule.escalate = true (default-deny)
 *
 *   input.action_type   → rule.action_type
 *   input.environment   → rule.environment
 *   input.<other>       → rule.conditions (object passthrough)
 *
 * Example input Rego:
 *
 *   package ovara.runtime
 *
 *   default allow = false
 *
 *   allow {
 *     input.action_type == "git.pull"
 *   }
 *
 *   allow {
 *     input.environment == "local"
 *     input.action_type == "shell"
 *   }
 *
 *   deny {
 *     input.environment == "production"
 *     input.action_type == "shell"
 *   }
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

export interface AdapterError {
  message: string;
  line?: number;
  source: 'lex' | 'parse' | 'semantic' | 'mapping';
}

interface RawRule {
  name: string;
  body: string;
  isDefault: boolean;
  defaultValue: boolean | null;
  line: number;
}

/**
 * Parse Rego source into a package name and a list of rules.
 *
 * The grammar we support is intentionally narrow — just enough to
 * translate the most common Rego patterns into Ovara policies:
 *
 *   package <name>
 *   default <ident> = true|false
 *   <ident> { <body> }
 *
 * Bodies are searched for `input.<field> == "value"` constraints. Each
 * such constraint becomes a field on the resulting Ovara rule. Bodies
 * with no input constraints produce a wildcard rule.
 */
function parseRego(source: string): { package: string; rules: RawRule[]; errors: AdapterError[] } {
  const errors: AdapterError[] = [];
  let pkg = '';
  const rules: RawRule[] = [];

  const lines = source.split('\n');
  let inBlock: { name: string; depth: number; body: string[]; isDefault: boolean; defaultValue: boolean | null; line: number } | null = null;
  let pendingDefault: { ident: string; value: boolean } | null = null;

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    const trimmed = line.trim();

    if (inBlock) {
      inBlock.body.push(line);
      for (const ch of line) {
        if (ch === '{') inBlock.depth++;
        else if (ch === '}') inBlock.depth--;
      }
      if (inBlock.depth <= 0) {
        rules.push({
          name: inBlock.name,
          body: inBlock.body.join('\n'),
          isDefault: inBlock.isDefault,
          defaultValue: inBlock.defaultValue,
          line: inBlock.line,
        });
        inBlock = null;
      }
      continue;
    }

    if (!trimmed || trimmed.startsWith('#')) continue;

    if (trimmed.startsWith('package ')) {
      pkg = trimmed.slice('package '.length).trim();
      continue;
    }

    const defaultMatch = trimmed.match(/^default\s+(\w+)\s*=\s*(true|false)\s*$/);
    if (defaultMatch) {
      // Always emit the default declaration as a rule (even if no body follows),
      // so the translator can detect default-allow/deny.
      rules.push({
        name: defaultMatch[1],
        body: '',
        isDefault: true,
        defaultValue: defaultMatch[2] === 'true',
        line: lineNum + 1,
      });
      pendingDefault = { ident: defaultMatch[1], value: defaultMatch[2] === 'true' };
      continue;
    }

    const ruleMatch = trimmed.match(/^(\w+)(?:\s*\([^)]*\))?\s*\{\s*$/);
    if (ruleMatch) {
      inBlock = {
        name: ruleMatch[1],
        depth: 1,
        body: [],
        isDefault: false,
        defaultValue: null,
        line: lineNum + 1,
      };
      // Consume the pending default if it matches — we don't need it anymore
      // since the default declaration was already pushed as a rule above.
      if (pendingDefault?.ident === ruleMatch[1]) {
        pendingDefault = null;
      }
      continue;
    }

    // Lone default declaration with no body was already pushed as a rule
    // when we encountered the `default` line. Just clear the pending state.
    if (pendingDefault && !trimmed.includes('{')) {
      pendingDefault = null;
      continue;
    }

    errors.push({ message: `unparseable line: ${trimmed}`, line: lineNum + 1, source: 'parse' });
  }

  if (inBlock) {
    errors.push({ message: `unterminated rule: ${inBlock.name}`, line: inBlock.line, source: 'parse' });
  }

  return { package: pkg, rules, errors };
}

/**
 * Extract input.<field> equality constraints from a rule body.
 * Supports expressions like:
 *   input.action_type == "git.pull"
 *   input.environment == "local"
 *   input.agent_id == "agt-001"
 */
function extractInputConditions(body: string): {
  actionType?: string;
  environment?: string;
  other: Record<string, string>;
} {
  const conditions: { actionType?: string; environment?: string; other: Record<string, string> } = { other: {} };
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = trimmed.match(/^input\.(\w+)\s*==\s*"([^"]*)"$/);
    if (!m) continue;
    const field = m[1];
    const value = m[2];
    if (field === 'action_type') conditions.actionType = value;
    else if (field === 'environment') conditions.environment = value;
    else conditions.other[field] = value;
  }
  return conditions;
}

function mapRule(rule: RawRule): OvaraRule {
  const conds = extractInputConditions(rule.body);
  const ovaraRule: OvaraRule = {
    action_type: conds.actionType ?? '*',
    environment: conds.environment ?? '*',
  };

  if (Object.keys(conds.other).length > 0) {
    ovaraRule.conditions = conds.other;
  }

  if (rule.name === 'allow') {
    ovaraRule.allow = true;
  } else if (rule.name === 'deny') {
    ovaraRule.deny = true;
  } else {
    ovaraRule.escalate = true;
  }

  ovaraRule.description = `Translated from OPA rule '${rule.name}' at line ${rule.line}`;

  return ovaraRule;
}

/**
 * Translate OPA (Rego) source to an Ovara policy.
 *
 * Throws an Error on parse or semantic failures.
 */
export function translateRego(rego: string): OvaraPolicy {
  if (!rego.trim()) {
    throw new Error('[opa-adapter:parse] empty policy');
  }

  const { package: pkg, rules, errors } = parseRego(rego);

  if (errors.length > 0) {
    const first = errors[0];
    throw new Error(`[opa-adapter:${first.source}] ${first.message} (line ${first.line})`);
  }

  if (!pkg) {
    throw new Error("[opa-adapter:semantic] missing 'package' declaration");
  }

  if (!pkg.startsWith('ovara')) {
    throw new Error(`[opa-adapter:semantic] package must start with 'ovara', got '${pkg}'`);
  }

  if (rules.length === 0) {
    throw new Error('[opa-adapter:semantic] no rules found');
  }

  // Default behavior: at least one default rule with name=allow and value=true
  const allowByDefault = rules.some(
    r => r.isDefault && r.name === 'allow' && r.defaultValue === true
  );

  // Explicit allow/deny rules (non-default, with a body)
  const explicitRules = rules.filter(
    r => !r.isDefault && (r.name === 'allow' || r.name === 'deny') && r.body.length > 0
  );

  if (explicitRules.length === 0) {
    return {
      version: 'v1-from-opa',
      rules: [
        {
          action_type: '*',
          environment: '*',
          allow: allowByDefault,
          escalate: !allowByDefault,
          description: `Translated from OPA package '${pkg}' (default ${allowByDefault ? 'allow' : 'deny'})`,
        },
      ],
    };
  }

  const ovaraRules = explicitRules.map(mapRule);

  // If the package default-deny (no default allow=true), add a catch-all
  // escalate to ensure unknown actions get a human review.
  if (!allowByDefault) {
    ovaraRules.push({
      action_type: '*',
      environment: '*',
      escalate: true,
      description: `OPA package '${pkg}' default-deny → catch-all escalate`,
    });
  }

  return {
    version: 'v1-from-opa',
    rules: ovaraRules,
  };
}

/**
 * Translate and return a JSON-serializable result suitable for writing
 * to a file.
 */
export function translateRegoJSON(rego: string): string {
  return JSON.stringify(translateRego(rego), null, 2);
}
