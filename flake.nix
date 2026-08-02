{
  description = "Pentect — local secret masking boundary for AI agents";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      release = builtins.fromJSON (builtins.readFile ./packaging/release.json);
      systems = builtins.attrNames release.systems;
      forAllSystems = function: nixpkgs.lib.genAttrs systems function;
      packageFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
          source = release.systems.${system};
        in
        pkgs.stdenvNoCC.mkDerivation {
          pname = "pentect";
          inherit (release) version;
          src = pkgs.fetchurl {
            inherit (source) url sha256;
          };
          dontUnpack = true;
          nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.glibc
            pkgs.stdenv.cc.cc.lib
          ];
          installPhase = ''
            runHook preInstall
            install -Dm755 "$src" "$out/bin/pentect"
            cat > "$out/bin/.pentect-managed-install.json" <<'JSON'
            {"version":1,"manager":"nix","update":"nix profile upgrade pentect","uninstall":"nix profile remove pentect"}
            JSON
            runHook postInstall
          '';
          meta = {
            description = "Local secret masking boundary for AI agents";
            homepage = "https://github.com/EdamAme-x/pentect";
            license = pkgs.lib.licenses.mit;
            mainProgram = "pentect";
            sourceProvenance = [ pkgs.lib.sourceTypes.binaryNativeCode ];
          };
        };
    in
    {
      packages = forAllSystems (system: {
        default = packageFor system;
        pentect = packageFor system;
      });
      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${packageFor system}/bin/pentect";
        };
        pentect = {
          type = "app";
          program = "${packageFor system}/bin/pentect";
        };
      });
    };
}
