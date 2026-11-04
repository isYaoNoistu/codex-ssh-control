import {randomUUID} from 'node:crypto';

// Ordinary task controls may run concurrently. Retirement requires exclusive
// access across MCP processes. PID reuse conservatively keeps a lease busy.
export function installLifecycleLocks(db) {
  db.exec('CREATE TABLE IF NOT EXISTS lifecycle_users(id TEXT NOT NULL, token TEXT PRIMARY KEY, pid INTEGER NOT NULL, exclusive INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS lifecycle_users_id ON lifecycle_users(id)');
}
export function transaction(db, action) {
  db.exec('BEGIN IMMEDIATE');
  try { const result=action(); db.exec('COMMIT'); return result; }
  catch(error) { db.exec('ROLLBACK'); throw error; }
}
export function occupants(db,id,table='lifecycle_users') {
  const rows=db.prepare(`SELECT * FROM ${table} WHERE id=?`).all(id);
  return rows.filter(row=>{
    try { process.kill(row.pid,0); }
    catch(error) {
      if(error.code==='ESRCH') { db.prepare(`DELETE FROM ${table} WHERE token=?`).run(row.token); return false; }
    }
    return true;
  });
}
export function takeLease(db,id,exclusive=false) {
  const token=randomUUID();
  transaction(db,()=>{
    if(occupants(db,id).some(row=>exclusive || row.exclusive)) throw Error('记录正在使用或回收，请稍后重试');
    db.prepare('INSERT INTO lifecycle_users VALUES(?,?,?,?)').run(id,token,process.pid,Number(exclusive));
  });
  return ()=>db.prepare('DELETE FROM lifecycle_users WHERE token=?').run(token);
}
