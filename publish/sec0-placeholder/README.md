# sec0-sdk

`sec0-sdk` is a minimal public starter package for the Sec0 SDK.

## Install

```bash
npm install sec0-sdk
```

## Usage

```js
const sec0Sdk = require("sec0-sdk");

console.log(sec0Sdk);
```

Output:

```json
{
  "name": "sec0-sdk",
  "stable": false,
  "message": "This is the initial public release of the Sec0 SDK package."
}
```

## Notes

This folder is publish-only and is intentionally not part of the workspace package graph.
Future releases can expand the package surface without changing the real workspace package today.
