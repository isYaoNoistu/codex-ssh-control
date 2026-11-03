export const INFRASTRUCTURE_DEFAULTS = {
  localRoots: [], actionArguments: {},
  jobs: {enabled:false,timeoutSeconds:3600,maxOutputKiB:1024,allowedShells:['/bin/sh'],allowedEnv:[],cpuSeconds:3600,maxMemoryMiB:2048,maxProcesses:128},
  transfers: {enabled:false,maxBytes:1073741824,maxEntries:256,timeoutSeconds:3600},
};
