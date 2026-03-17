export const SEC0_PACKAGE_NAME = "sec0" as const;
export const SEC0_RESERVED = true as const;
export const SEC0_RESERVED_MESSAGE =
  "The sec0 package name is reserved. A fuller public package will be published here later." as const;

export interface Sec0PackageInfo {
  name: typeof SEC0_PACKAGE_NAME;
  reserved: typeof SEC0_RESERVED;
  message: typeof SEC0_RESERVED_MESSAGE;
}

export function getSec0PackageInfo(): Sec0PackageInfo {
  return {
    name: SEC0_PACKAGE_NAME,
    reserved: SEC0_RESERVED,
    message: SEC0_RESERVED_MESSAGE,
  };
}

const sec0 = getSec0PackageInfo();

export default sec0;
