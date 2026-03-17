# sec0

`sec0` is a minimal placeholder package published to reserve the npm package name.

## Install

```bash
npm install sec0
```

## What It Exports

The package currently exports a small metadata object and helper:

```ts
import sec0, { getSec0PackageInfo } from "sec0";

console.log(sec0);
console.log(getSec0PackageInfo());
```

Both return:

```json
{
  "name": "sec0",
  "reserved": true,
  "message": "The sec0 package name is reserved. A fuller public package will be published here later."
}
```

## Why It Is Minimal

This package exists primarily to reserve the `sec0` npm name until the fuller public package is ready.
