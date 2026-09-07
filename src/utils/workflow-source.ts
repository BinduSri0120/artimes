import { parse, type Node } from 'acorn';

import type { SanitizerPolicy } from './sanitize.js';

const WORKFLOW_SOURCE_PATH = /(?:^|\.)nodes\[\d+\]\.config\.code$/;
const SENSITIVE_SOURCE_KEY =
  /^(?:api[_-]?key|x[_-]?api[_-]?key|secret|credential|private[_-]?key|access[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|auth|authorization|proxy[_-]?authorization|password|token|cookie|set[_-]?cookie)$/i;
const EMBEDDED_CREDENTIAL_ASSIGNMENT =
  /\b(api[_-]?key|x[_-]?api[_-]?key|secret|credential|private[_-]?key|access[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|authorization|proxy[_-]?authorization|password|token|cookie|set[_-]?cookie)["'`]?\s*[:=]\s*(?!(?:bearer|basic)\b)(?:"((?:\\.|[^"\\])+)"|'((?:\\.|[^'\\])+)'|`((?:\\.|[^`\\])+)`|([^\s,;]+))/gi;
const EMBEDDED_AUTH_SCHEME = /\b(bearer|basic)\s+([^\s,;"'`]+)/gi;
const EMBEDDED_URL_CREDENTIALS = /(https?:\/\/)[^\s/@:"'`]+:[^\s/@"'`]+@/gi;
const BENIGN_CREDENTIAL_LITERAL =
  /^(?:disabled|unavailable|none|null|undefined|false|true|not[-_ ]?configured)$/i;
const BENIGN_AUTH_MODE =
  /^(?:oauth2?|oidc|saml|basic|bearer|jwt|api[_-]?key|token|cookie|password|certificate|mtls|kerberos|ntlm|digest)$/i;
const SENTINEL_COMPATIBLE_TARGET =
  /^(?:api[_-]?key|x[_-]?api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|auth|authorization|proxy[_-]?authorization|token|cookie|set[_-]?cookie)$/i;
const SOURCE_WRAPPER_PREFIX = 'async function __arch_workflow_source__() {\n';
const SOURCE_WRAPPER_SUFFIX = '\n}';

interface AstNode extends Node {
  readonly [key: string]: unknown;
}

interface SourceSpan {
  readonly start: number;
  readonly end: number;
  readonly replacement: string;
}

export function isWorkflowSourceCodePath(path: string): boolean {
  return WORKFLOW_SOURCE_PATH.test(path);
}

export function redactEmbeddedWorkflowCredentialLiterals(value: string): string {
  let tree: AstNode;
  const comments: Array<{ block: boolean; text: string; start: number; end: number }> = [];
  try {
    tree = parse(`${SOURCE_WRAPPER_PREFIX}${value}${SOURCE_WRAPPER_SUFFIX}`, {
      ecmaVersion: 'latest',
      sourceType: 'script',
      onComment: (block, text, start, end) => comments.push({ block, text, start, end }),
    }) as unknown as AstNode;
  } catch {
    return '[REDACTED]';
  }

  const replacements = new Map<string, SourceSpan>();
  visitAst(tree, (node) => {
    if (node.type === 'VariableDeclarator') {
      addSensitiveValue(node.id, node.init, value, replacements);
    } else if (node.type === 'AssignmentExpression') {
      addSensitiveValue(node.left, node.right, value, replacements);
    } else if (node.type === 'Property') {
      addSensitiveValue(node.key, node.value, value, replacements);
    } else if (node.type === 'AssignmentPattern') {
      addSensitiveValue(node.left, node.right, value, replacements);
    } else if (node.type === 'PropertyDefinition') {
      addSensitiveValue(node.key, node.value, value, replacements);
    } else if (node.type === 'MethodDefinition') {
      addSensitiveValue(node.key, node.value, value, replacements);
    } else if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      addSensitiveCallArgument(node, value, replacements);
    }

    const span = stringSpan(node, value);
    if (!span) return;
    const content = value.slice(span.start, span.end);
    const redacted = redactCredentialText(content);
    if (redacted !== content && !replacements.has(`${span.start}:${span.end}`)) {
      setReplacement(replacements, { ...span, replacement: redacted });
    }
  });

  for (const comment of comments) {
    if (redactCredentialText(comment.text) === comment.text) continue;
    const delimiterLength = 2;
    const start = comment.start - SOURCE_WRAPPER_PREFIX.length + delimiterLength;
    const end = comment.end - SOURCE_WRAPPER_PREFIX.length - (comment.block ? delimiterLength : 0);
    if (start >= 0 && end >= start && end <= value.length) {
      setReplacement(replacements, { start, end, replacement: '[REDACTED]' });
    }
  }

  let result = value;
  const spans = [...replacements.values()].sort((left, right) => right.start - left.start);
  for (const span of spans) {
    result = `${result.slice(0, span.start)}${span.replacement}${result.slice(span.end)}`;
  }
  return result;
}

export function containsEmbeddedWorkflowCredentialLiteral(value: string): boolean {
  return redactEmbeddedWorkflowCredentialLiterals(value) !== value;
}

function visitAst(node: AstNode, visitor: (node: AstNode) => void): void {
  visitor(node);
  for (const [key, value] of Object.entries(node)) {
    if (key === 'type' || key === 'start' || key === 'end') continue;
    if (Array.isArray(value)) {
      for (const child of value) {
        if (isAstNode(child)) visitAst(child, visitor);
      }
    } else if (isAstNode(value)) {
      visitAst(value, visitor);
    }
  }
}

function isAstNode(value: unknown): value is AstNode {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

function addSensitiveValue(
  key: unknown,
  valueNode: unknown,
  source: string,
  replacements: Map<string, SourceSpan>,
): void {
  const targetName = sensitiveTargetName(key);
  if (!targetName || !isAstNode(valueNode)) return;
  if (isFunctionNode(valueNode)) {
    addFunctionReturnValues(targetName, valueNode, source, replacements);
    return;
  }
  const staticValue = staticStringValue(valueNode);
  if (staticValue !== undefined && isBenignCredentialLiteral(targetName, staticValue)) return;
  const span = stringSpan(valueNode, source);
  if (span) {
    setReplacement(replacements, { ...span, replacement: '[REDACTED]' });
    return;
  }
  if (staticValue !== undefined) {
    const start = valueNode.start - SOURCE_WRAPPER_PREFIX.length;
    const end = valueNode.end - SOURCE_WRAPPER_PREFIX.length;
    if (start < 0 || end < start || end > source.length) return;
    setReplacement(replacements, { start, end, replacement: '"[REDACTED]"' });
    return;
  }
  addSensitiveExpressionValues(targetName, valueNode, source, replacements);
}

function addFunctionReturnValues(
  targetName: string,
  valueNode: AstNode,
  source: string,
  replacements: Map<string, SourceSpan>,
): void {
  if (
    valueNode.type === 'ArrowFunctionExpression' &&
    isAstNode(valueNode.body) &&
    valueNode.body.type !== 'BlockStatement'
  ) {
    addSensitiveExpressionValues(targetName, valueNode.body, source, replacements);
    return;
  }
  visitSameFunctionScope(valueNode, valueNode, (child) => {
    if (child.type === 'ReturnStatement' && isAstNode(child.argument)) {
      addSensitiveExpressionValues(targetName, child.argument, source, replacements);
    }
  });
}

function visitSameFunctionScope(
  root: AstNode,
  node: AstNode,
  visitor: (node: AstNode) => void,
): void {
  visitor(node);
  for (const [key, value] of Object.entries(node)) {
    if (key === 'type' || key === 'start' || key === 'end') continue;
    for (const child of Array.isArray(value) ? value : [value]) {
      if (!isAstNode(child) || (child !== root && isFunctionNode(child))) continue;
      visitSameFunctionScope(root, child, visitor);
    }
  }
}

function addSensitiveExpressionValues(
  targetName: string,
  node: AstNode,
  source: string,
  replacements: Map<string, SourceSpan>,
): void {
  if (node.type === 'ConditionalExpression') {
    if (isAstNode(node.consequent))
      addSensitiveExpressionValues(targetName, node.consequent, source, replacements);
    if (isAstNode(node.alternate))
      addSensitiveExpressionValues(targetName, node.alternate, source, replacements);
    return;
  }
  if (node.type === 'LogicalExpression') {
    if (isAstNode(node.left))
      addSensitiveExpressionValues(targetName, node.left, source, replacements);
    if (isAstNode(node.right))
      addSensitiveExpressionValues(targetName, node.right, source, replacements);
    return;
  }
  if (node.type === 'BinaryExpression') {
    if (isAstNode(node.left))
      addSensitiveExpressionValues(targetName, node.left, source, replacements);
    if (isAstNode(node.right))
      addSensitiveExpressionValues(targetName, node.right, source, replacements);
    return;
  }
  if (node.type === 'SpreadElement' && isAstNode(node.argument)) {
    addSensitiveExpressionValues(targetName, node.argument, source, replacements);
    return;
  }
  if (node.type === 'ArrayExpression') {
    const elements = Array.isArray(node.elements) ? node.elements : [];
    for (const element of elements) {
      if (isAstNode(element))
        addSensitiveExpressionValues(targetName, element, source, replacements);
    }
    return;
  }
  if (node.type === 'ObjectExpression') {
    const properties = Array.isArray(node.properties) ? node.properties : [];
    for (const property of properties) {
      if (isAstNode(property) && property.type === 'Property' && isAstNode(property.value)) {
        addSensitiveExpressionValues(targetName, property.value, source, replacements);
      } else if (
        isAstNode(property) &&
        property.type === 'SpreadElement' &&
        isAstNode(property.argument)
      ) {
        addSensitiveExpressionValues(targetName, property.argument, source, replacements);
      }
    }
    return;
  }
  if (node.type === 'SequenceExpression') {
    const expressions = Array.isArray(node.expressions) ? node.expressions : [];
    const last = expressions.at(-1);
    if (isAstNode(last)) addSensitiveExpressionValues(targetName, last, source, replacements);
    return;
  }
  if (
    (node.type === 'AwaitExpression' || node.type === 'ChainExpression') &&
    isAstNode(node.argument ?? node.expression)
  ) {
    addSensitiveExpressionValues(
      targetName,
      (node.argument ?? node.expression) as AstNode,
      source,
      replacements,
    );
    return;
  }
  if (node.type === 'CallExpression' || node.type === 'NewExpression') {
    if (node.type === 'CallExpression' && isAstNode(node.callee)) {
      if (isFunctionNode(node.callee)) {
        addFunctionReturnValues(targetName, node.callee, source, replacements);
      } else if (node.callee.type === 'MemberExpression') {
        addMemberReceiverValues(targetName, node.callee, source, replacements);
      }
    }
    const args = Array.isArray(node.arguments) ? node.arguments : [];
    for (const argument of args) {
      if (isAstNode(argument))
        addSensitiveExpressionValues(targetName, argument, source, replacements);
    }
    return;
  }
  if (node.type === 'MemberExpression') {
    addMemberReceiverValues(targetName, node, source, replacements);
    return;
  }
  if (node.type === 'AssignmentExpression' && isAstNode(node.right)) {
    addSensitiveExpressionValues(targetName, node.right, source, replacements);
    return;
  }
  if (node.type === 'TaggedTemplateExpression' && isAstNode(node.quasi)) {
    if (node.quasi.type === 'TemplateLiteral' && staticStringValue(node.quasi) === undefined) {
      const start = node.quasi.start - SOURCE_WRAPPER_PREFIX.length;
      const end = node.quasi.end - SOURCE_WRAPPER_PREFIX.length;
      if (start >= 0 && end >= start && end <= source.length) {
        setReplacement(replacements, { start, end, replacement: '`[REDACTED]`' });
      }
      return;
    }
    addSensitiveExpressionValues(targetName, node.quasi, source, replacements);
    return;
  }
  if (node.type === 'TemplateLiteral') {
    const staticSpan = stringSpan(node, source);
    if (staticSpan) {
      setReplacement(replacements, { ...staticSpan, replacement: '[REDACTED]' });
      return;
    }
    const start = node.start - SOURCE_WRAPPER_PREFIX.length;
    const end = node.end - SOURCE_WRAPPER_PREFIX.length;
    if (start >= 0 && end >= start && end <= source.length) {
      setReplacement(replacements, { start, end, replacement: '"[REDACTED]"' });
    }
    return;
  }
  if (isFunctionNode(node)) {
    addFunctionReturnValues(targetName, node, source, replacements);
    return;
  }
  const span = stringSpan(node, source);
  if (!span) return;
  const value = source.slice(span.start, span.end);
  if (isBenignCredentialLiteral(targetName, value)) return;
  setReplacement(replacements, { ...span, replacement: '[REDACTED]' });
}

function addMemberReceiverValues(
  targetName: string,
  member: AstNode,
  source: string,
  replacements: Map<string, SourceSpan>,
): void {
  if (!isAstNode(member.object)) return;
  const object = member.object;
  if (object.type === 'ArrayExpression') {
    const elements = Array.isArray(object.elements) ? object.elements : [];
    for (const element of elements) {
      if (isAstNode(element))
        addSensitiveExpressionValues(targetName, element, source, replacements);
    }
    return;
  }
  if (object.type === 'ObjectExpression') {
    const requestedKey = isAstNode(member.property)
      ? String(member.property.name ?? staticStringValue(member.property) ?? '')
      : '';
    const properties = Array.isArray(object.properties) ? object.properties : [];
    for (const property of properties) {
      if (
        isAstNode(property) &&
        property.type === 'SpreadElement' &&
        isAstNode(property.argument)
      ) {
        addSensitiveExpressionValues(targetName, property.argument, source, replacements);
        continue;
      }
      if (!isAstNode(property) || property.type !== 'Property') continue;
      const propertyKey = isAstNode(property.key)
        ? String(property.key.name ?? staticStringValue(property.key) ?? '')
        : '';
      if (propertyKey === requestedKey && isAstNode(property.value)) {
        addSensitiveExpressionValues(targetName, property.value, source, replacements);
      }
    }
    return;
  }
  addSensitiveExpressionValues(targetName, object, source, replacements);
}

function sensitiveTargetName(node: unknown): string | undefined {
  if (!isAstNode(node)) return undefined;
  if (node.type === 'Identifier' || node.type === 'PrivateIdentifier') {
    const name = String(node.name);
    return SENSITIVE_SOURCE_KEY.test(name) ? name : undefined;
  }
  const staticValue = staticStringValue(node);
  if (staticValue !== undefined)
    return SENSITIVE_SOURCE_KEY.test(staticValue) ? staticValue : undefined;
  if (node.type === 'MemberExpression') return sensitiveTargetName(node.property);
  return undefined;
}

function isFunctionNode(node: unknown): boolean {
  return (
    isAstNode(node) &&
    (node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression' ||
      node.type === 'FunctionDeclaration')
  );
}

function addSensitiveCallArgument(
  node: AstNode,
  source: string,
  replacements: Map<string, SourceSpan>,
): void {
  const args = Array.isArray(node.arguments) ? node.arguments : [];
  if (
    node.type === 'NewExpression' &&
    isAstNode(node.callee) &&
    /^Headers$/i.test(terminalCalleeName(node.callee))
  ) {
    if (isAstNode(args[0]) && args[0].type === 'SpreadElement' && isAstNode(args[0].argument)) {
      for (const argument of flattenedArrayElements(args[0].argument)) {
        addHeaderTuples(argument, source, replacements);
      }
    } else {
      addHeaderTuples(args[0], source, replacements);
    }
    return;
  }
  let keyNode = args[0];
  let valueNode = args[1];
  if (
    args.length === 1 &&
    isAstNode(args[0]) &&
    args[0].type === 'SpreadElement' &&
    isAstNode(args[0].argument)
  ) {
    const spreadValues = flattenedArrayElements(args[0].argument);
    keyNode = spreadValues[0];
    valueNode = spreadValues[1];
  }
  if (!isAstNode(keyNode) || !isAstNode(valueNode)) return;
  const key = staticStringValue(keyNode);
  if (!key || !SENSITIVE_SOURCE_KEY.test(key)) return;
  if (!isAstNode(node.callee)) return;
  const calleeName =
    node.callee.type === 'Identifier'
      ? String(node.callee.name)
      : node.callee.type === 'MemberExpression' && isAstNode(node.callee.property)
        ? String(node.callee.property.name ?? staticStringValue(node.callee.property) ?? '')
        : '';
  const receiver =
    node.callee.type === 'MemberExpression' && isAstNode(node.callee.object)
      ? node.callee.object
      : undefined;
  const receiverName =
    receiver?.type === 'Identifier'
      ? String(receiver.name)
      : receiver?.type === 'MemberExpression' && isAstNode(receiver.property)
        ? String(receiver.property.name ?? staticStringValue(receiver.property) ?? '')
        : '';
  const createsHeaders =
    receiver?.type === 'NewExpression' &&
    isAstNode(receiver.callee) &&
    /^Headers$/i.test(terminalCalleeName(receiver.callee));
  const getsHeaders =
    receiver?.type === 'CallExpression' &&
    isAstNode(receiver.callee) &&
    /^(?:get|create)?Headers$/i.test(terminalCalleeName(receiver.callee));
  if (
    !/^setHeader$/i.test(calleeName) &&
    (!/^(?:set|append)$/i.test(calleeName) ||
      (!/headers?$/i.test(receiverName) && !createsHeaders && !getsHeaders))
  ) {
    return;
  }
  addSensitiveValue(keyNode, valueNode, source, replacements);
}

function addHeaderTuples(
  node: unknown,
  source: string,
  replacements: Map<string, SourceSpan>,
): void {
  if (
    isAstNode(node) &&
    node.type === 'NewExpression' &&
    isAstNode(node.callee) &&
    /^Map$/i.test(terminalCalleeName(node.callee))
  ) {
    const args = Array.isArray(node.arguments) ? node.arguments : [];
    if (isAstNode(args[0]) && args[0].type === 'SpreadElement' && isAstNode(args[0].argument)) {
      for (const argument of flattenedArrayElements(args[0].argument)) {
        addHeaderTuples(argument, source, replacements);
      }
    } else {
      addHeaderTuples(args[0], source, replacements);
    }
    return;
  }
  if (!isAstNode(node) || node.type !== 'ArrayExpression') return;
  const tuples = flattenedArrayElements(node);
  for (const tuple of tuples) {
    if (!isAstNode(tuple) || tuple.type !== 'ArrayExpression') continue;
    const values = flattenedArrayElements(tuple);
    if (isAstNode(values[0]) && isAstNode(values[1])) {
      addSensitiveValue(values[0], values[1], source, replacements);
    }
  }
}

function flattenedArrayElements(node: AstNode): unknown[] {
  if (node.type !== 'ArrayExpression') return [];
  const result: unknown[] = [];
  const elements = Array.isArray(node.elements) ? node.elements : [];
  for (const element of elements) {
    if (isAstNode(element) && element.type === 'SpreadElement' && isAstNode(element.argument)) {
      result.push(...flattenedArrayElements(element.argument));
    } else {
      result.push(element);
    }
  }
  return result;
}

function terminalCalleeName(node: AstNode): string {
  if (node.type === 'Identifier') return String(node.name);
  if (node.type === 'MemberExpression' && isAstNode(node.property)) {
    return String(node.property.name ?? staticStringValue(node.property) ?? '');
  }
  return '';
}

function staticStringValue(node: AstNode): string | undefined {
  const value = staticPrimitiveValue(node);
  return typeof value === 'string' ? value : undefined;
}

function staticPrimitiveValue(node: AstNode): string | number | boolean | null | undefined {
  if (
    node.type === 'Literal' &&
    (typeof node.value === 'string' ||
      typeof node.value === 'number' ||
      typeof node.value === 'boolean' ||
      node.value === null)
  ) {
    return node.value;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    if (!isAstNode(node.left) || !isAstNode(node.right)) return undefined;
    const left = staticPrimitiveValue(node.left);
    const right = staticPrimitiveValue(node.right);
    if (left === undefined || right === undefined) return undefined;
    return typeof left === 'string' || typeof right === 'string'
      ? String(left) + String(right)
      : Number(left) + Number(right);
  }
  if (node.type !== 'TemplateLiteral') return undefined;
  const expressions = Array.isArray(node.expressions) ? node.expressions : [];
  const quasis = Array.isArray(node.quasis) ? node.quasis : [];
  if (quasis.length !== expressions.length + 1) return undefined;
  let result = '';
  for (let index = 0; index < quasis.length; index += 1) {
    if (!isAstNode(quasis[index])) return undefined;
    const cooked = (quasis[index].value as { cooked?: unknown } | undefined)?.cooked;
    if (typeof cooked !== 'string') return undefined;
    result += cooked;
    if (index < expressions.length) {
      if (!isAstNode(expressions[index])) return undefined;
      const expression = staticPrimitiveValue(expressions[index]);
      if (expression === undefined) return undefined;
      result += String(expression);
    }
  }
  return result;
}

function stringSpan(node: AstNode, source: string): SourceSpan | undefined {
  if (node.type !== 'Literal' && node.type !== 'TemplateLiteral') return undefined;
  if (staticStringValue(node) === undefined) return undefined;
  const start = node.start - SOURCE_WRAPPER_PREFIX.length + 1;
  const end = node.end - SOURCE_WRAPPER_PREFIX.length - 1;
  if (start < 0 || end < start || end > source.length) return undefined;
  return { start, end, replacement: '' };
}

function isLikelyCredential(candidate: string): boolean {
  const normalized = candidate
    .replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, '')
    .replace(/-based$/i, '');
  return !/^(?:authentication|authorization|credentials?|tokens?|access|rfc|mechanism|scheme|header|for|with|using)$/i.test(
    normalized,
  );
}

function isBenignCredentialLiteral(targetName: string, value: string): boolean {
  return (
    (SENTINEL_COMPATIBLE_TARGET.test(targetName) && BENIGN_CREDENTIAL_LITERAL.test(value.trim())) ||
    (/^auth$/i.test(targetName) && BENIGN_AUTH_MODE.test(value.trim()))
  );
}

function setReplacement(replacements: Map<string, SourceSpan>, candidate: SourceSpan): void {
  for (const [key, existing] of replacements) {
    if (existing.start <= candidate.start && existing.end >= candidate.end) return;
    if (candidate.start <= existing.start && candidate.end >= existing.end)
      replacements.delete(key);
  }
  replacements.set(`${candidate.start}:${candidate.end}`, candidate);
}

function redactCredentialText(content: string): string {
  return content
    .replace(EMBEDDED_AUTH_SCHEME, (match, scheme: string, candidate: string, offset: number) => {
      const preceding = content.slice(Math.max(0, offset - 64), offset);
      const explicitAuthorization = /\bauthorization\s*[:=]\s*$/i.test(preceding);
      return explicitAuthorization || isLikelyCredential(candidate)
        ? `${scheme} [REDACTED]`
        : match;
    })
    .replace(EMBEDDED_URL_CREDENTIALS, '$1[REDACTED]@')
    .replace(
      EMBEDDED_CREDENTIAL_ASSIGNMENT,
      (
        match,
        key: string,
        doubleQuoted: string | undefined,
        singleQuoted: string | undefined,
        templateQuoted: string | undefined,
        unquoted: string | undefined,
      ) => {
        const candidate = doubleQuoted ?? singleQuoted ?? templateQuoted ?? unquoted ?? '';
        return isBenignCredentialLiteral(key, candidate) ? match : `${key}=[REDACTED]`;
      },
    );
}

export const WORKFLOW_SOURCE_SANITIZER_POLICY: SanitizerPolicy = Object.freeze({
  preserveStringAtPath: isWorkflowSourceCodePath,
  containsSensitiveStringAtPath: containsEmbeddedWorkflowCredentialLiteral,
  sanitizeStringAtPath: redactEmbeddedWorkflowCredentialLiterals,
});
