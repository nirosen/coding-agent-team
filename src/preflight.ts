import fs from "node:fs";
import { spawnSync } from "node:child_process";

export type CapacityCheck = {
  label: string;
  path: string;
  availableGb: number;
};

function availableGb(targetPath: string): number {
  const stats = fs.statfsSync(targetPath);
  return Number(stats.bavail) * Number(stats.bsize) / 1024 ** 3;
}

function assertCapacity(
  label: string,
  targetPath: string,
  minimumGb: number,
): CapacityCheck {
  const free = availableGb(targetPath);
  if (free < minimumGb) {
    throw new Error(
      `${label} has ${free.toFixed(1)}GB free at ${targetPath}; minimum is ${minimumGb}GB`,
    );
  }
  return { label, path: targetPath, availableGb: free };
}

export function runHostPreflight(opts: {
  cwd: string;
  minimumFreeGb: number;
  requireDocker: boolean;
}): CapacityCheck[] {
  if (
    !Number.isFinite(opts.minimumFreeGb) ||
    opts.minimumFreeGb < 0 ||
    opts.minimumFreeGb > 100_000
  ) {
    throw new Error("--min-free-gb must be a finite number between 0 and 100000");
  }
  const checks = [
    assertCapacity("workspace filesystem", opts.cwd, opts.minimumFreeGb),
  ];

  const docker = spawnSync(
    "docker",
    ["info", "--format", "{{.DockerRootDir}}"],
    {
      encoding: "utf8",
      timeout: 10_000,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (docker.status !== 0) {
    if (opts.requireDocker) {
      throw new Error(
        `Docker is required but unavailable: ${(docker.stderr || docker.error?.message || "docker info failed").trim()}`,
      );
    }
    return checks;
  }

  const dockerRoot = docker.stdout.trim();
  if (!dockerRoot) {
    if (opts.requireDocker) throw new Error("Docker root directory is empty");
    return checks;
  }
  try {
    checks.push(
      assertCapacity(
        "Docker filesystem",
        dockerRoot,
        opts.minimumFreeGb,
      ),
    );
  } catch (error) {
    if (opts.requireDocker) throw error;
    console.warn(
      `[preflight] could not validate Docker filesystem: ${error instanceof Error ? error.message : error}`,
    );
  }
  return checks;
}
