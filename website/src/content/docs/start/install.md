---
title: Install
description: Install Pentect on Windows, macOS, or Linux.
---

## Windows

Run in PowerShell:

```powershell
irm https://pentect.dev/install | iex
```

## macOS and Linux

::: code-group

```sh [Shell]
curl -fsSL https://pentect.dev/install.sh | sh
```

```sh [Homebrew]
brew install EdamAme-x/pentect/pentect
```

```sh [Nix · temporary shell]
nix shell github:EdamAme-x/pentect
```

```sh [Nix · profile]
nix profile install github:EdamAme-x/pentect
```

```sh [npm]
npm install --global github:EdamAme-x/pentect
```

```sh [Cargo · build from source]
cargo install --git https://github.com/EdamAme-x/pentect --locked pentect-cli
```

```sh [APT repository · Debian / Ubuntu]
# First install: adds the Pentect repository and installs the package
curl -fsSL https://pentect.dev/install-apt.sh | sudo sh

# Later updates use APT directly
sudo apt update
sudo apt install --only-upgrade pentect
```

:::

The direct installers detect the current platform, download a GitHub Release
asset, and verify its SHA-256 checksum.

The npm package installs the same checksummed release binary. `nix shell` opens
a temporary environment without adding Pentect to your profile. Cargo builds
Pentect from source and therefore takes longer than the binary installers.

## NixOS configuration

With a flake-based NixOS configuration, add Pentect as an input and include its
package in a module where `inputs` and `pkgs` are available:

```nix
# flake.nix
inputs.pentect.url = "github:EdamAme-x/pentect";

# configuration.nix or another NixOS module
environment.systemPackages = [
  inputs.pentect.packages.${pkgs.system}.default
];
```

Then rebuild the same flake configuration you normally use:

```sh
sudo nixos-rebuild switch --flake .#HOSTNAME
```

This keeps Pentect declarative and pinned by `flake.lock`. Update the input with
`nix flake update pentect`, review the lockfile change, and rebuild.

## Verify the installation

```sh
pentect doctor
```

`doctor` checks whether Pentect and supported clients are ready. If it reports
a repairable problem, review the proposed change before using:

```sh
pentect doctor --fix
```

## Install a specific version

::: code-group

```powershell [Windows]
& ([scriptblock]::Create((irm https://pentect.dev/install))) -Version X.Y.Z
```

```sh [macOS / Linux]
curl -fsSL https://pentect.dev/install.sh | sh -s -- --version X.Y.Z
```

:::

::: info
When Pentect was installed through Homebrew, Nix, or apt, update and uninstall
it through the same package manager.
:::

Package-manager updates:

::: code-group

```sh [Homebrew]
brew update
brew upgrade pentect
```

```sh [APT]
sudo apt update
sudo apt install --only-upgrade pentect
```

```sh [Nix profile]
nix profile upgrade pentect
```

```sh [NixOS flake]
nix flake update pentect
sudo nixos-rebuild switch --flake .#HOSTNAME
```

:::

## Update or uninstall

```sh
pentect update
pentect update X.Y.Z
pentect uninstall
```
