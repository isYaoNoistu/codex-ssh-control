export function confirmedJob(record) {
  return record.observation === 'confirmed' &&
    ['completed', 'failed', 'cancelled'].includes(record.status) &&
    !['identity_lost', 'supervisor_lost', 'timeout'].includes(record.terminationReason);
}

export function confirmedTransfer(record) {
  return record.status === 'completed' ||
    (record.status === 'cancelled' && !record.unresolvedCommit &&
      (record.cancelConfirmed === true || record.cancelledBeforeDispatch === true));
}

export function verifiedStorage(value, collect) {
  if (!value || value.collected !== collect ||
      !['bytes', 'retainedBytes', 'reclaimedBytes'].every(key => Number.isSafeInteger(value[key]) && value[key] >= 0) ||
      value.retainedBytes + value.reclaimedBytes !== value.bytes ||
      (!collect && value.reclaimedBytes !== 0) ||
      (value.missing && (collect || value.bytes !== 0))) {
    throw new Error('Remote private storage response was not verified');
  }
  return {bytes: value.bytes, retainedBytes: value.retainedBytes, reclaimedBytes: value.reclaimedBytes,
    collected: collect, ...(value.missing === true ? {missing: true} : {})};
}
