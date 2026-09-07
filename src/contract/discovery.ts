import { createHash } from 'node:crypto';
import {
  getToolContracts,
  type PublishedToolContract,
  type ToolDiscoveryProfile,
} from '../tools/index.js';
import { ARCH_MCP_SERVER_VERSION } from '../tools/persona.js';

export const ARCH_CONTRACT_URI_PREFIX = 'arch://contract/v2/' as const;
export const ARCH_CONTRACT_MANIFEST_URI = `${ARCH_CONTRACT_URI_PREFIX}manifest` as const;
export const ARCH_CONTRACT_MEDIA_TYPE =
  'application/vnd.kore.arch-mcp-contract+json;version=2' as const;

export interface ArchContractDiscoveryMeta {
  readonly profile: ToolDiscoveryProfile;
  readonly manifestUri: typeof ARCH_CONTRACT_MANIFEST_URI;
  readonly runtimeContract: 'unchanged';
}

export interface ArchContractManifest {
  readonly schemaVersion: 2;
  readonly profile: ToolDiscoveryProfile;
  readonly serverVersion: string;
  readonly runtimeContract: 'unchanged';
  readonly compatibility: {
    readonly targetlessRequests: 'preserved';
    readonly unknownResponseFields: 'ignored';
    readonly legacyFallbackProfile: 'legacy-v1';
  };
  readonly features: {
    readonly evalTargets: boolean;
    readonly lockedTargetSnapshots: boolean;
  };
  readonly toolCount: number;
  readonly contractHashes: Readonly<Record<string, string>>;
}

export function isContractResourceUri(uri: string): boolean {
  return uri.startsWith(ARCH_CONTRACT_URI_PREFIX);
}

export function getContractDiscoveryMeta(profile: ToolDiscoveryProfile): ArchContractDiscoveryMeta {
  return {
    profile,
    manifestUri: ARCH_CONTRACT_MANIFEST_URI,
    runtimeContract: 'unchanged',
  };
}

export function listContractResources() {
  return [
    {
      uri: ARCH_CONTRACT_MANIFEST_URI,
      name: 'contract-manifest-v2',
      title: 'Arch MCP contract manifest',
      description: 'Machine-readable compatibility and feature metadata for the active profile.',
      mimeType: ARCH_CONTRACT_MEDIA_TYPE,
    },
  ];
}

export function readContractResource(uri: string, profile: ToolDiscoveryProfile) {
  if (uri !== ARCH_CONTRACT_MANIFEST_URI) {
    throw new Error(`Unknown Arch contract resource: ${uri}`);
  }

  const contracts = getToolContracts(profile);
  const manifest: ArchContractManifest = {
    schemaVersion: 2,
    profile,
    serverVersion: ARCH_MCP_SERVER_VERSION,
    runtimeContract: 'unchanged',
    compatibility: {
      targetlessRequests: 'preserved',
      unknownResponseFields: 'ignored',
      legacyFallbackProfile: 'legacy-v1',
    },
    features: {
      evalTargets: profile === 'current-v2',
      lockedTargetSnapshots: profile === 'current-v2',
    },
    toolCount: contracts.length,
    contractHashes: Object.fromEntries(
      contracts.map((contract) => [contract.name, hashContract(contract)]),
    ),
  };

  const text = JSON.stringify(manifest);
  return {
    contents: [{ uri, mimeType: ARCH_CONTRACT_MEDIA_TYPE, text }],
  };
}

function hashContract(contract: PublishedToolContract): string {
  return createHash('sha256').update(JSON.stringify(contract)).digest('hex');
}
