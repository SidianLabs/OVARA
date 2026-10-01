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
/**
 * Strip `#` comments from a line while preserving `#` characters that
 * appear inside quoted strings.
 */
function stripComment(line: string): string {
  let inStr = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i - 1] !== '\\') inStr = !inStr;
    else if (ch === '#' && !inStr) return line.slice(0, i);
  }
  return line;
}

function parseRego(source: string): { package: string; rules: RawRule[]; errors: AdapterError[] } {
  const errors: AdapterError[] = [];
  let pkg = '';
  const rules: RawRule[] = [];

  const lines = source.split('\n');
  let inBlock: { name: string; depth: number; body: string[]; isDefault: boolean; defaultValue: boolean | null; line: number } | null = null;
  let pendingDefault: { ident: string; value: boolean } | null = null;
  let lastRuleName: string | null = null;
  let lastRuleLine = 0;

  const pushRule = (name: string, body: string[], line: number) => {
    rules.push({ name, body: body.join('\n'), isDefault: false, defaultValue: null, line });
    lastRuleName = name;
    lastRuleLine = line;
  };

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = stripComment(lines[lineNum]);
    const trimmed = line.trim();

    if (inBlock) {
      inBlock.body.push(line);
      for (const ch of line) {
        if (ch === '{') inBlock.depth++;
        else if (ch === '}') inBlock.depth--;
      }
      if (inBlock.depth <= 0) {
        pushRule(inBlock.name, inBlock.body, inBlock.line);
        inBlock = null;
      }
      continue;
    }

    if (!trimmed) continue;

    if (trimmed.startsWith('package ')) {
      pkg = trimmed.slice('package '.length).trim();
      continue;
    }

    // `import rego.v1`, `import future.keywords.*`, `import data.x` — imports
    // affect name resolution only; our supported grammar needs none of them.
    if (/^import\s+/.test(trimmed)) continue;

    const defaultMatch = trimmed.match(/^default\s+(\w+)\s*(?::=|=)\s*(true|false)\s*$/);
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

    // `else` / `else <expr>` / `else if {` — continue the previous rule.
    // Semantically `else` only fires when the prior body failed; treating it
    // as an independent rule of the same name over-denies for `deny` (safe,
    // fail-closed) but would over-allow for `allow`, which we reject.
    const elseMatch = trimmed.match(/^else\b(.*)$/);
    if (elseMatch) {
      if (!lastRuleName) {
        errors.push({ message: `'else' without preceding rule`, line: lineNum + 1, source: 'parse' });
        continue;
      }
      if (lastRuleName !== 'deny') {
        errors.push({
          message: `'else' after '${lastRuleName}' is untranslatable (would broaden ${lastRuleName}); only deny-chains are supported`,
          line: lastRuleLine, source: 'semantic',
        });
        continue;
      }
      const rest = elseMatch[1].trim();
      const braceIdx = rest.indexOf('{');
      if (braceIdx === -1) {
        errors.push({ message: `unparseable else head: ${trimmed}`, line: lineNum + 1, source: 'parse' });
        continue;
      }
      const head = rest.slice(0, braceIdx).trim();
      if (head && head !== 'if') {
        errors.push({ message: `unparseable else head: ${trimmed}`, line: lineNum + 1, source: 'parse' });
        continue;
      }
      const afterBrace = rest.slice(braceIdx + 1);
      const closeIdx = afterBrace.indexOf('}');
      if (closeIdx !== -1) {
        // Single-line else: `else { exprs }`
        pushRule('deny', [afterBrace.slice(0, closeIdx)], lineNum + 1);
      } else {
        inBlock = {
          name: 'deny', depth: 1,
          body: afterBrace.trim() ? [afterBrace] : [],
          isDefault: false, defaultValue: null, line: lineNum + 1,
        };
      }
      continue;
    }

    // Rule heads:
    //   name {                 name if {              name if <exprs>
    //   name(args) {           name contains x if {   (rejected below)
    const headMatch = trimmed.match(/^(\w+)(?:\s*\([^)]*\))?(?:\s+contains\s+\S+)?(?:\s+if\b)?\s*(.*)$/);
    if (headMatch) {
      const name = headMatch[1];
      const rest = headMatch[2].trim();

      if (/\bcontains\b/.test(trimmed.slice(name.length).split('{')[0])) {
        errors.push({
          message: `partial-set rule '${name} contains ...' is untranslatable to a boolean Ovara rule`,
          line: lineNum + 1, source: 'semantic',
        });
        continue;
      }

      if (rest.startsWith('{')) {
        const afterBrace = rest.slice(1);
        const closeIdx = afterBrace.indexOf('}');
        if (closeIdx !== -1) {
          // Single-line rule: `name if { exprs }`
          pushRule(name, [afterBrace.slice(0, closeIdx)], lineNum + 1);
        } else {
          inBlock = {
            name, depth: 1,
            body: afterBrace.trim() ? [afterBrace] : [],
            isDefault: false, defaultValue: null, line: lineNum + 1,
          };
        }
        if (pendingDefault?.ident === name) pendingDefault = null;
        continue;
      }

      // `name if` with no body — invalid Rego, do not treat as unconditional.
      if (/\bif\b/.test(trimmed) && !rest) {
        errors.push({ message: `unparseable rule head: ${trimmed}`, line: lineNum + 1, source: 'parse' });
        continue;
      }

      // `name if <exprs>` — single-line rule with inline body.
      if (/\bif\b/.test(trimmed) && rest) {
        pushRule(name, [rest], lineNum + 1);
        if (pendingDefault?.ident === name) pendingDefault = null;
        continue;
      }

      // Bare `name` line (e.g. `allow` alone = unconditional true) is a
      // boolean assignment in Rego; map it to an unconditional rule.
      if (rest === '' && (name === 'allow' || name === 'deny')) {
        pushRule(name, [], lineNum + 1);
        if (pendingDefault?.ident === name) pendingDefault = null;
        continue;
      }
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
function extractInputConditions(body: string, ruleName: string, ruleLine: number): {
  actionType?: string;
  environment?: string;
  other: Record<string, string>;
} {
  const conditions: { actionType?: string; environment?: string; other: Record<string, string> } = { other: {} };

  // Local `ident := "literal"` bindings we can substitute into constraints.
  const vars: Record<string, string> = {};

  const setField = (field: string, value: string) => {
    if (field === 'action_type') conditions.actionType = value;
    else if (field === 'environment') conditions.environment = value;
    else conditions.other[field] = value;
  };

  // Split the body into expressions: Rego joins body expressions with
  // newlines or `;`.
  const exprs = body.split(/[;\n]/);

  for (const raw of exprs) {
    const e = stripComment(raw).trim();
    // Skip blank lines, comments, and bare braces.
    if (!e || /^[{}]*$/.test(e)) continue;

    const fail = () => {
      // Fail closed: an expression we cannot translate must not be silently
      // dropped, or the resulting rule would be broader than the source.
      throw new Error(
        `[opa-adapter:semantic] unhandled body expression in rule '${ruleName}': ${e} (line ${ruleLine})`
      );
    };

    // `x := "literal"` local binding — record for later substitution.
    let m = e.match(/^([a-zA-Z_]\w*)\s*:=\s*"([^"]*)"$/);
    if (m) { vars[m[1]] = m[2]; continue; }
    m = e.match(/^([a-zA-Z_]\w*)\s*:=\s*(\d+(?:\.\d+)?)$/);
    if (m) { vars[m[1]] = m[2]; continue; }
    // `x := input.field` — alias; record with input. prefix.
    m = e.match(/^([a-zA-Z_]\w*)\s*:=\s*(input\.\w+)$/);
    if (m) { vars[m[1]] = m[2]; continue; }

    // `some x` / `some x, y` declarations only introduce variables used
    // elsewhere — safe to skip. `some x in ...` iteration is NOT (it adds
    // an existential constraint we cannot express).
    if (/^some\s+[\w,\s]+$/.test(e)) continue;
    if (/^some\b/.test(e)) fail();

    // `input.field[_] == "v"` array-membership — untranslatable without
    // knowing which element matched; fail closed.
    if (/\[\s*[_\w]*\s*\]/.test(e)) fail();

    // startswith/endswith/contains on an input field → glob in conditions.
    m = e.match(/^(startswith|endswith|contains)\(\s*input\.(\w+)\s*,\s*"([^"]*)"\s*\)$/);
    if (m) {
      const [, fn, field, val] = m;
      setField(field, fn === 'startswith' ? `${val}*` : fn === 'endswith' ? `*${val}` : `*${val}*`);
      continue;
    }

    // Comparisons on input fields: ==, !=, >, <, >=, <=.
    m = e.match(/^input\.(\w+)\s*(==|!=|>=|<=|>|<)\s*"([^"]*)"$/);
    if (m) {
      const [, field, op, val] = m;
      setField(field, op === '==' ? val : `${op}${val}`);
      continue;
    }
    m = e.match(/^input\.(\w+)\s*(==|!=|>=|<=|>|<)\s*(\d+(?:\.\d+)?)$/);
    if (m) {
      const [, field, op, val] = m;
      setField(field, op === '==' ? val : `${op}${val}`);
      continue;
    }

    // Comparison against a bound variable: `input.field == x`.
    m = e.match(/^input\.(\w+)\s*(==|!=)\s*([a-zA-Z_]\w*)$/);
    if (m && m[3] in vars) {
      const bound = vars[m[3]];
      // Variable aliasing another input field → field-to-field comparison,
      // which we cannot express. Fail closed.
      if (bound.startsWith('input.')) fail();
      setField(m[1], m[2] === '==' ? bound : `${m[2]}${bound}`);
      continue;
    }
    // `x == "v"` where x aliases input.field.
    m = e.match(/^([a-zA-Z_]\w*)\s*==\s*"([^"]*)"$/);
    if (m && m[1] in vars && vars[m[1]].startsWith('input.')) {
      setField(vars[m[1]].slice('input.'.length), m[2]);
      continue;
    }

    fail();
  }
  return conditions;
}

function mapRule(rule: RawRule): OvaraRule {
  const conds = extractInputConditions(rule.body, rule.name, rule.line);
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

  if (pkg !== 'ovara' && !pkg.startsWith('ovara.')) {
    throw new Error(`[opa-adapter:semantic] package must start with 'ovara' or 'ovara.', got '${pkg}'`);
  }

  if (rules.length === 0) {
    throw new Error('[opa-adapter:semantic] no rules found');
  }

  // Default behavior: at least one default rule with name=allow and value=true
  const allowByDefault = rules.some(
    r => r.isDefault && r.name === 'allow' && r.defaultValue === true
  );

  // Explicit allow/deny rules (non-default). An empty body means the rule
  // is unconditional (e.g. a bare `allow` line) and maps to a wildcard.
  const explicitRules = rules.filter(
    r => !r.isDefault && (r.name === 'allow' || r.name === 'deny')
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

  // Emit deny rules before allow rules: Ovara evaluates denies with
  // priority, and ordering them first preserves fail-closed semantics.
  const mapped = explicitRules.map(mapRule);
  const ovaraRules = [
    ...mapped.filter(r => r.deny),
    ...mapped.filter(r => !r.deny),
  ];

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
