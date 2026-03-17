export type SecurityConfigLike = {
  egress_allowlist?: string[];
  fs_allowlist?: string[];
  limits?: { max_payload_kb?: number };
  deny_subprocess?: boolean;
};

function matchesAny(value: string, patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) return true;
  return patterns.some((p) => {
    const esc = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*?");
    try {
      return new RegExp(`^${esc}$`, "i").test(value);
    } catch {
      return true;
    }
  });
}

export function estimateSizeKb(obj: unknown): number {
  try {
    return Math.ceil(Buffer.byteLength(JSON.stringify(obj || {}), "utf8") / 1024);
  } catch {
    return 0;
  }
}

function buildUrlFromHttpArgs(args: any[]): string | undefined {
  try {
    const a0 = args[0];
    if (typeof a0 === "string") return a0;
    if (a0 && typeof a0 === "object" && a0.href && typeof a0.href === "string") return a0.href;
    const opts = a0 && typeof a0 === "object" ? a0 : args[1] && typeof args[1] === "object" ? args[1] : undefined;
    if (!opts) return undefined;
    const protocol = opts.protocol || (opts.agent && opts.agent.protocol) || "http:";
    const host = opts.hostname || opts.host || opts.servername;
    if (!host) return undefined;
    const port = opts.port ? `:${opts.port}` : "";
    const path = typeof opts.path === "string" ? opts.path : "/";
    return `${protocol}//${host}${port}${path}`;
  } catch {
    return undefined;
  }
}

export async function withGuardedIO<T>(sec: SecurityConfigLike, fn: () => Promise<T>): Promise<T> {
  const http = require("node:http");
  const https = require("node:https");
  const fs = require("node:fs");
  const cp = require("node:child_process");

  const originals = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpGet: http.get,
    httpsRequest: https.request,
    httpsGet: https.get,
    fsWriteFile: fs.writeFile,
    fsReadFile: fs.readFile,
    fsUnlink: fs.unlink,
    fsMkdir: fs.mkdir,
    fsRename: fs.rename,
    fsRmdir: fs.rmdir,
    pWriteFile: fs.promises?.writeFile,
    pReadFile: fs.promises?.readFile,
    pUnlink: fs.promises?.unlink,
    pMkdir: fs.promises?.mkdir,
    pRename: fs.promises?.rename,
    pRmdir: fs.promises?.rmdir,
    spawn: cp.spawn,
    exec: cp.exec,
    execFile: cp.execFile,
  } as any;

  const throwViolation = (code: string, info?: Record<string, any>) => {
    const err: any = new Error(code);
    err.code = code;
    if (info) Object.assign(err, info);
    throw err;
  };

  const installHttpGuards = () => {
    if (!sec.egress_allowlist) return;
    const guardUrl = (urlStr?: string) => {
      if (!urlStr) return;
      if (!matchesAny(urlStr, sec.egress_allowlist)) throwViolation("egress_violation", { url: urlStr });
    };
    http.request = (...a: any[]) => {
      guardUrl(buildUrlFromHttpArgs(a));
      return originals.httpRequest(...a);
    };
    http.get = (...a: any[]) => {
      guardUrl(buildUrlFromHttpArgs(a));
      return originals.httpGet(...a);
    };
    https.request = (...a: any[]) => {
      guardUrl(buildUrlFromHttpArgs(a));
      return originals.httpsRequest(...a);
    };
    https.get = (...a: any[]) => {
      guardUrl(buildUrlFromHttpArgs(a));
      return originals.httpsGet(...a);
    };
    if (typeof globalThis.fetch === "function") {
      (globalThis as any).fetch = ((input: any, init?: any) => {
        const urlStr = typeof input === "string" ? input : input && typeof input.url === "string" ? input.url : undefined;
        guardUrl(urlStr);
        return originals.fetch(input, init);
      }) as any;
    }
  };

  const installFsGuards = () => {
    if (!sec.fs_allowlist) return;
    const guardPath = (p?: any) => {
      const pathStr = typeof p === "string" ? p : undefined;
      if (!pathStr) return;
      if (!matchesAny(pathStr, sec.fs_allowlist)) throwViolation("fs_violation", { path: pathStr });
    };
    fs.writeFile = (...a: any[]) => {
      guardPath(a[0]);
      return originals.fsWriteFile(...a);
    };
    fs.readFile = (...a: any[]) => {
      guardPath(a[0]);
      return originals.fsReadFile(...a);
    };
    fs.unlink = (...a: any[]) => {
      guardPath(a[0]);
      return originals.fsUnlink(...a);
    };
    fs.mkdir = (...a: any[]) => {
      guardPath(a[0]);
      return originals.fsMkdir(...a);
    };
    fs.rename = (...a: any[]) => {
      guardPath(a[0]);
      guardPath(a[1]);
      return originals.fsRename(...a);
    };
    if (fs.rmdir) {
      fs.rmdir = (...a: any[]) => {
        guardPath(a[0]);
        return originals.fsRmdir(...a);
      };
    }
    if (fs.promises) {
      if (fs.promises.writeFile) {
        fs.promises.writeFile = (...a: any[]) => {
          guardPath(a[0]);
          return originals.pWriteFile(...a);
        };
      }
      if (fs.promises.readFile) {
        fs.promises.readFile = (...a: any[]) => {
          guardPath(a[0]);
          return originals.pReadFile(...a);
        };
      }
      if (fs.promises.unlink) {
        fs.promises.unlink = (...a: any[]) => {
          guardPath(a[0]);
          return originals.pUnlink(...a);
        };
      }
      if (fs.promises.mkdir) {
        fs.promises.mkdir = (...a: any[]) => {
          guardPath(a[0]);
          return originals.pMkdir(...a);
        };
      }
      if (fs.promises.rename) {
        fs.promises.rename = (...a: any[]) => {
          guardPath(a[0]);
          guardPath(a[1]);
          return originals.pRename(...a);
        };
      }
      if (fs.promises.rmdir) {
        fs.promises.rmdir = (...a: any[]) => {
          guardPath(a[0]);
          return originals.pRmdir(...a);
        };
      }
    }
  };

  const installSubprocessGuards = () => {
    if (sec.deny_subprocess === false) return;
    cp.spawn = () => {
      throwViolation("subprocess_blocked");
    };
    cp.exec = () => {
      throwViolation("subprocess_blocked");
    };
    cp.execFile = () => {
      throwViolation("subprocess_blocked");
    };
  };

  try {
    installHttpGuards();
    installFsGuards();
    installSubprocessGuards();
    return await fn();
  } finally {
    http.request = originals.httpRequest;
    http.get = originals.httpGet;
    https.request = originals.httpsRequest;
    https.get = originals.httpsGet;
    if (typeof originals.fetch === "function") {
      (globalThis as any).fetch = originals.fetch;
    }
    const fs = require("node:fs");
    const cp = require("node:child_process");
    fs.writeFile = originals.fsWriteFile;
    fs.readFile = originals.fsReadFile;
    fs.unlink = originals.fsUnlink;
    fs.mkdir = originals.fsMkdir;
    fs.rename = originals.fsRename;
    if (originals.fsRmdir) fs.rmdir = originals.fsRmdir;
    if (fs.promises) {
      if (originals.pWriteFile) fs.promises.writeFile = originals.pWriteFile;
      if (originals.pReadFile) fs.promises.readFile = originals.pReadFile;
      if (originals.pUnlink) fs.promises.unlink = originals.pUnlink;
      if (originals.pMkdir) fs.promises.mkdir = originals.pMkdir;
      if (originals.pRename) fs.promises.rename = originals.pRename;
      if (originals.pRmdir) fs.promises.rmdir = originals.pRmdir;
    }
    cp.spawn = originals.spawn;
    cp.exec = originals.exec;
    cp.execFile = originals.execFile;
  }
}
