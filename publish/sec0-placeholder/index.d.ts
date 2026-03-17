export declare const SEC0_SDK_PACKAGE_NAME: "sec0-sdk";
export declare const SEC0_SDK_STABLE: false;
export declare const SEC0_SDK_MESSAGE: "This is the initial public release of the Sec0 SDK package.";

export interface Sec0SdkPackageInfo {
  name: typeof SEC0_SDK_PACKAGE_NAME;
  stable: typeof SEC0_SDK_STABLE;
  message: typeof SEC0_SDK_MESSAGE;
}

export declare function getSec0SdkPackageInfo(): Sec0SdkPackageInfo;

declare const sec0Sdk: Sec0SdkPackageInfo;

export default sec0Sdk;
