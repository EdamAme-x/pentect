---
title: Install
description: Install Pentect on Windows, macOS, or Linux.
---

import { Tabs, TabItem, Steps, Aside } from '@astrojs/starlight/components';

<Tabs>
  <TabItem label="Windows">
    Run in PowerShell:

    ```powershell
    irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1 | iex
    ```
  </TabItem>
  <TabItem label="macOS / Linux">
    ```sh
    curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh
    ```
  </TabItem>
  <TabItem label="Homebrew">
    ```sh
    brew install EdamAme-x/pentect/pentect
    ```
  </TabItem>
  <TabItem label="Nix">
    ```sh
    nix profile install github:EdamAme-x/pentect
    ```
  </TabItem>
  <TabItem label="Debian / Ubuntu">
    ```sh
    curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install-apt.sh | sudo sh
    ```
  </TabItem>
</Tabs>

The direct installers detect the current platform, download a GitHub Release
asset, and verify its SHA-256 checksum.

## Verify the installation

```text
pentect doctor
```

`doctor` checks whether Pentect and supported clients are ready. If it reports
a repairable problem, review the proposed change before using:

```text
pentect doctor --fix
```

## Install a specific version

<Tabs>
  <TabItem label="Windows">
    ```powershell
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1))) -Version X.Y.Z
    ```
  </TabItem>
  <TabItem label="macOS / Linux">
    ```sh
    curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh -s -- --version X.Y.Z
    ```
  </TabItem>
</Tabs>

<Aside type="note">
  When Pentect was installed through Homebrew, Nix, or apt, update and uninstall
  it through the same package manager.
</Aside>

## Update or uninstall

```text
pentect update
pentect update X.Y.Z
pentect uninstall
```
