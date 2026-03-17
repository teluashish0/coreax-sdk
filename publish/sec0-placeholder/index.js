"use strict";

const SEC0_SDK_PACKAGE_NAME = "sec0-sdk";
const SEC0_SDK_STABLE = false;
const SEC0_SDK_MESSAGE =
  "This is the initial public release of the Sec0 SDK package.";

const packageInfo = Object.freeze({
  name: SEC0_SDK_PACKAGE_NAME,
  stable: SEC0_SDK_STABLE,
  message: SEC0_SDK_MESSAGE,
});

function getSec0SdkPackageInfo() {
  return packageInfo;
}

module.exports = {
  ...packageInfo,
  default: packageInfo,
  getSec0SdkPackageInfo,
  SEC0_SDK_PACKAGE_NAME,
  SEC0_SDK_STABLE,
  SEC0_SDK_MESSAGE,
};
