import {jobHelperCommand} from './job-service.mjs';
import {confirmedJob, confirmedTransfer, verifiedStorage} from './terminal-evidence.mjs';

// Internal adapters. The caller holds the local lifecycle fence and a current
// policy/host permit. IDs, tokens, paths, and deadlines come from the owned row.
export async function inspectJobPrivate(service, record, collect = false) {
  if (collect && !confirmedJob(record)) {
    throw new Error('Only a confirmed terminal job can be collected');
  }
  const request = {action: collect ? 'collect' : 'storage', id: record.id,
    token: record.token, expectedStatus: record.status};
  const response = await service.execute(record.host, jobHelperCommand, {
    input: JSON.stringify(request), timeoutSeconds: 20, maxOutputBytes: 4096,
  });
  if (response.exitCode !== 0 || response.truncated) throw new Error('Remote private job state could not be verified');
  const result = JSON.parse(response.stdout);
  if (result.error) throw new Error('Remote private job state could not be verified or is still in use');
  return verifiedStorage(result, collect);
}

export async function inspectTransferPrivate(service, record, collect = false) {
  if (collect && !confirmedTransfer(record)) {
    throw new Error('Only a confirmed terminal transfer can be collected');
  }
  if (record.direction === 'download') {
    // Downloads never stage data or receipts on the server.
    return {bytes: 0, retainedBytes: 0, reclaimedBytes: 0, collected: collect};
  }
  if (record.direction !== 'upload') throw new Error('Unknown transfer direction');
  // A short maintenance request has its own authorization. It does not renew
  // the original transfer; GC also checks the original expiry on the server.
  const maintenance = {...record, status: 'maintenance', expiresAt: service.clock() + 30000};
  const result = await service._metadata(maintenance, collect ? 'collect' : 'storage',
    {expectedStatus: record.status, originalExpiresAt: record.expiresAt});
  return verifiedStorage(result, collect);
}
