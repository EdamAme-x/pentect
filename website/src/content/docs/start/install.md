---
title: Install
description: Install Pentect on Windows, macOS, or Linux.
---

## Windows

Run in PowerShell:

```powershell
irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1 | iex
```

## macOS and Linux

::: code-group

```sh [Shell]
curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh
```

```sh [Homebrew]
brew install EdamAme-x/pentect/pentect
```

```sh [Nix]
nix profile install github:EdamAme-x/pentect
```

```sh [APT · Debian / Ubuntu]
curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install-apt.sh | sudo sh
```

:::

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

::: code-group

```powershell [Windows]
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1))) -Version X.Y.Z
```

```sh [macOS / Linux]
curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh -s -- --version X.Y.Z
```

:::

::: info
When Pentect was installed through Homebrew, Nix, or apt, update and uninstall
it through the same package manager.
:::

## Update or uninstall

```text
pentect update
pentect update X.Y.Z
pentect uninstall
```
