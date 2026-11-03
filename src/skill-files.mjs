import { lstatSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, rmdirSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { renderHostSkill, EXPLICIT_SKILL_POLICY } from './shortcuts.mjs';

// Stable on-disk ownership identifiers preserve existing generated skills after renaming.
const OWNER = 'ssh-sidebar-control';
const MARKER = '.ssh-control-owner.json';
const FILES = ['SKILL.md', 'agents/openai.yaml'];
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function statIfPresent(target) {
  try { return lstatSync(target); } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function assertNoLinks(target) {
  const absolute = path.resolve(target);
  let current = path.parse(absolute).root;
  const parts = path.relative(current, absolute).split(path.sep).filter(Boolean);
  for (const part of parts) {
    current = path.join(current, part);
    const info = statIfPresent(current);
    if (!info) continue;
    if (info.isSymbolicLink()) throw new Error('目录或文件包含符号链接，已保留原内容');
  }
}

function inside(root, ...parts) {
  const target = path.resolve(root, ...parts);
  const relative = path.relative(root, target);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('生成路径超出技能目录');
  }
  return target;
}

function readRegular(target, maxBytes = 1024 * 1024) {
  assertNoLinks(target);
  const info = statIfPresent(target);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > maxBytes) {
    throw new Error('生成文件缺失、类型异常或过大，已保留原内容');
  }
  return readFileSync(target, 'utf8');
}

function verifyOwned(root, directory, hostId) {
  assertNoLinks(directory);
  if (!statIfPresent(directory)?.isDirectory()) throw new Error('同名路径不是普通技能目录');
  const markerPath = inside(root, path.relative(root, directory), MARKER);
  if (!statIfPresent(markerPath)) throw new Error('同名技能不属于本插件，未覆盖');
  const marker = JSON.parse(readRegular(markerPath, 8192));
  if (marker.owner !== OWNER || marker.schema !== 1 || marker.hostId !== hostId
      || !marker.files || typeof marker.files !== 'object' || Array.isArray(marker.files)
      || Object.keys(marker.files).sort().join('|') !== [...FILES].sort().join('|')) {
    throw new Error('技能所有权标记无效，已保留原内容');
  }
  const contents = {};
  for (const file of FILES) {
    const target = inside(root, path.relative(root, directory), file);
    const text = readRegular(target);
    if (!/^[a-f0-9]{64}$/.test(marker.files[file]) || sha256(text) !== marker.files[file]) {
      throw new Error('生成文件已被修改，已保留原内容');
    }
    contents[file] = text;
  }
  return contents;
}

function atomicWrite(root, target, content) {
  inside(root, path.relative(root, target));
  assertNoLinks(target);
  const existing = statIfPresent(target);
  if (existing && !existing.isFile()) throw new Error('目标文件类型异常');
  const temporary = inside(root, path.relative(root, path.dirname(target)), `.ssh-control-${randomUUID()}.tmp`);
  let created = false;
  try {
    writeFileSync(temporary, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    created = true;
    assertNoLinks(target);
    renameSync(temporary, target);
    created = false;
  } finally {
    // Only unlink the exact temporary file we created, never a directory tree.
    if (created && statIfPresent(temporary)) {
      assertNoLinks(path.dirname(temporary));
      unlinkSync(temporary);
    }
  }
}

function updateSkill(root, id, content) {
  const name = `ssh-${id}`;
  const directory = inside(root, name);
  const expected = { 'SKILL.md': content, 'agents/openai.yaml': EXPLICIT_SKILL_POLICY };
  const existing = statIfPresent(directory);
  if (existing) {
    const previous = verifyOwned(root, directory, id);
    if (FILES.every((file) => previous[file] === expected[file])) return false;
  } else {
    assertNoLinks(root);
    mkdirSync(directory, { mode: 0o700 });
  }
  const marker = { owner: OWNER, schema: 1, hostId: id, files: Object.fromEntries(FILES.map((file) => [file, sha256(expected[file])])) };
  // A fresh directory becomes owned before its first generated skill file is written.
  if (!existing) atomicWrite(root, inside(root, name, MARKER), `${JSON.stringify(marker, null, 2)}\n`);
  const agents = inside(root, name, 'agents');
  assertNoLinks(agents);
  if (!statIfPresent(agents)) mkdirSync(agents, { mode: 0o700 });
  for (const file of FILES) atomicWrite(root, inside(root, name, file), expected[file]);
  atomicWrite(root, inside(root, name, MARKER), `${JSON.stringify(marker, null, 2)}\n`);
  return true;
}

function removeSkill(root, name, id) {
  const directory = inside(root, name);
  verifyOwned(root, directory, id);
  for (const file of [...FILES, MARKER]) {
    const target = inside(root, name, file);
    assertNoLinks(target);
    unlinkSync(target);
  }
  const agents = inside(root, name, 'agents');
  assertNoLinks(agents);
  if (readdirSync(agents).length === 0) rmdirSync(agents);
  assertNoLinks(directory);
  if (readdirSync(directory).length === 0) {
    rmdirSync(directory);
    return false;
  }
  return true;
}

function errorMessage(error) {
  return error?.code ? `文件操作失败（${error.code}）` : (error instanceof SyntaxError ? '所有权标记格式无效' : error.message);
}

export function syncHostSkills(hosts, root = process.env.SSH_CONTROL_SKILLS || path.join(homedir(), '.agents', 'skills')) {
  const result = { root, written: [], removed: [], warnings: [] };
  const desired = new Map();
  try {
    if (!Array.isArray(hosts)) throw new Error('主机目录无效');
    for (const host of hosts) desired.set(host?.id, renderHostSkill(host));
    if (typeof root !== 'string' || !root.trim() || /[\0\r\n]/.test(root)) throw new Error('快捷技能目录无效');
    root = path.resolve(root);
    result.root = root;
    assertNoLinks(root);
    if (!statIfPresent(root)) {
      if (!desired.size) return result;
      mkdirSync(root, { recursive: true, mode: 0o700 });
    }
    assertNoLinks(root);
    if (!statIfPresent(root)?.isDirectory()) throw new Error('快捷技能根路径不是目录');
  } catch (error) {
    result.warnings.push(`快捷技能同步未执行：${errorMessage(error)}`);
    return result;
  }
  for (const [id, content] of [...desired].sort(([a], [b]) => a.localeCompare(b))) {
    try {
      if (updateSkill(root, id, content)) result.written.push(`ssh-${id}`);
    } catch (error) { result.warnings.push(`ssh-${id}：${errorMessage(error)}`); }
  }
  try {
    for (const entry of readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!/^ssh-[a-z][a-z0-9-]{0,47}$/.test(entry.name)) continue;
      const id = entry.name.slice(4);
      if (desired.has(id)) continue;
      if (entry.isSymbolicLink()) {
        result.warnings.push(`${entry.name}：符号链接未清理`);
        continue;
      }
      if (!entry.isDirectory()) continue;
      const marker = inside(root, entry.name, MARKER);
      if (!statIfPresent(marker)) continue;
      try {
        const kept = removeSkill(root, entry.name, id);
        result.removed.push(entry.name);
        if (kept) result.warnings.push(`${entry.name}：生成文件已清理，保留用户添加的其他文件`);
      } catch (error) { result.warnings.push(`${entry.name}：${errorMessage(error)}`); }
    }
  } catch (error) { result.warnings.push(`快捷技能清理未完成：${errorMessage(error)}`); }
  return result;
}