---
title: Install Pentect
description: Install and update Pentect on Windows, macOS, or Linux.
pageClass: install-page
---

Choose your operating system and package manager. Pentect uses a prebuilt
binary, so the install does not compile the Rust workspace on your machine.

<HomeInstall />

## Check the install

```sh
pentect doctor
```

`doctor` checks Pentect and the AI clients installed on your machine. To apply
a fix after reviewing it, run `pentect doctor --fix`.

## Start a client

Use Pentect for one session:

```sh
pentect codex
# or
pentect claude
```

To keep the shorter client command, ask Pentect to update your shell profile:

```sh
pentect codex --set-default
pentect claude --set-default
```

The change is shown before approval and can be removed later with
`--unset-default`. See [Quick start](/start/quick-start/) for the full flow.

If you use a desktop App often, install a separate protected launcher:

```sh
pentect codex app --install-launcher
pentect claude app --install-launcher
```

The launcher is optional. It appears as `Codex via Pentect` or `Claude via
Pentect` and does not replace the official App. Quit the official App before
opening the protected launcher.

## Install a specific version

Use the same installer with a version number:

::: code-group

```powershell [PowerShell]
& ([scriptblock]::Create((irm https://pentect.dev/install))) -Version X.Y.Z
```

```sh [Shell]
curl -fsSL https://pentect.dev/install.sh | sh -s -- --version X.Y.Z
```

```sh [npm]
npm i -g pentect@X.Y.Z
```

:::

Homebrew, APT, and Nix choose versions through their normal package-manager
workflow. A Nix flake lock file keeps the selected revision.

## Update

Use the package manager that installed Pentect:

::: code-group

```sh [Direct installer]
pentect update

# Or choose a version
pentect update X.Y.Z
```

```sh [npm]
npm update -g pentect
```

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

## NixOS configuration

Add Pentect to your flake input and system packages:

```nix
# flake.nix
inputs.pentect.url = "github:EdamAme-x/pentect";

outputs = inputs@{ nixpkgs, ... }: {
  nixosConfigurations.HOSTNAME = nixpkgs.lib.nixosSystem {
    specialArgs = { inherit inputs; };
    modules = [ ./configuration.nix ];
  };
};

# configuration.nix
{ pkgs, inputs, ... }:
{
  environment.systemPackages = [
    inputs.pentect.packages.${pkgs.system}.default
  ];
}
```

Then rebuild with the host name from your flake:

```sh
sudo nixos-rebuild switch --flake .#HOSTNAME
```

## Uninstall

Remove any shell defaults or App launchers first:

```sh
pentect codex --unset-default
pentect claude --unset-default
pentect codex app --remove-launcher
pentect claude app --remove-launcher
```

For a direct PowerShell or shell install:

```sh
pentect uninstall
```

For npm, Homebrew, APT, or Nix, uninstall Pentect with that package manager.
Project `.pentect` settings and user data are not removed automatically.
