---
title: Build a plugin
description: Start a Pentect plugin and test it locally.
---

1. Create a plugin project.

   ```text
   pentect plugins new my-plugin
   ```

2. Run it from the local directory.

   ```text
   pentect plugins dev ./my-plugin
   ```

3. Test its declared behavior and permissions.

   ```text
   pentect plugins test my-plugin
   pentect plugins inspect my-plugin
   ```

4. Publish the prepared plugin.

   ```text
   pentect plugins publish ./my-plugin
   ```

## Choose the smallest plugin form

Use a manifest-only regex detector when matching and labeling spans is enough.
Choose Wasm middleware only when you need context, branching, configuration, or
control over whether the next middleware runs.

The Rust SDK is published as
[`pentect-plugin`](https://crates.io/crates/pentect-plugin).

::: info
Plugin permissions are part of the user-facing security contract. Declare
only the access the plugin needs; installation approval is not a substitute
for narrow permissions.
:::
