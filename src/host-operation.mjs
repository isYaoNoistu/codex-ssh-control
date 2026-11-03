import { normalizeOperation, resolveSafeCommand } from './policy.mjs';

export function normalizeHostOperation(input, host) {
  const operation = normalizeOperation(input);
  // Omission inherits the saved directory; an explicit empty cwd keeps SSH's login directory.
  // Catalog aliases already isolate their execution and never inherit host defaults.
  if (operation.kind === 'command' && input.cwd === undefined && !resolveSafeCommand(operation.command)) {
    return normalizeOperation({ ...operation, cwd: host?.defaultCwd ?? '' });
  }
  if(operation.kind==='job'&&input.cwd===undefined)return normalizeOperation({...operation,cwd:host?.defaultCwd||'/'});
  return operation;
}
