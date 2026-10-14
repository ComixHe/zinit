# SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
#
# SPDX-License-Identifier: MIT

{
  description = "A tiny init for Linux containers";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  # This only fetches released artifacts, it never builds from source. The
  # binary is linked statically, so there is nothing to patch and no runtime
  # dependency to pull in. And what `nix build` installs is the artifact published on GitHub.
  #
  # The hashes are from the SHA256SUMS of the release named below. Update all
  # four of them together with the tag: one per architecture, one per mode.
  #
  # NixOS has no official support for riscv64-linux architecture on the
  # nixpkgs-unstable and stable channel.

  outputs =
    { self, nixpkgs }:
    let
      release = "v0.2.1";

      manifest = builtins.replaceStrings [ "\n" ] [ " " ] (builtins.readFile ./build.zig.zon);
      version =
        let
          m = builtins.match ".*\\.version = \"([^\"]+)\".*" manifest;
        in
        if m == null then throw "build.zig.zon has no .version" else builtins.head m;

      # `small` is what the artifact image ships. `safe` keeps the runtime safety
      # checks, so an out-of-bounds access aborts instead of behaving undefined
      modes = {
        small = "ReleaseSmall";
        safe = "ReleaseSafe";
      };

      sources = {
        x86_64-linux = {
          small = "sha256-gr9DGkwOC+X8fpDDWoJiM6D1tLglf35B4MuuJ34/abs=";
          safe = "sha256-iY2p3LkoAC45pfewv8l8+olmuq6N3jaHuF2VFZPoAE0=";
        };
        aarch64-linux = {
          small = "sha256-5X0AKMxFjmA8urRH+61xceJc7GOMe9FTDfNUQMbxe4s=";
          safe = "sha256-tBWwn8FAqx8N3a0vLNsjo992OQc3+ugXCkJ/W8m52Tk=";
        };
      };

      systems = builtins.attrNames sources;
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          mkPackage =
            mode:
            let
              modeName = modes.${mode};
              tarball = "zinit-${version}-${system}-${modeName}.tar.gz";
              unpacked = "zinit-${version}-${system}-${modeName}";
              suffix = nixpkgs.lib.optionalString (mode == "safe") "-safe";
            in
            pkgs.runCommand "zinit-${version}${suffix}"
              {
                meta = {
                  description =
                    "A tiny, libc-less init for Linux containers"
                    + nixpkgs.lib.optionalString (mode == "safe") " (runtime safety checks)";
                  homepage = "https://github.com/ComixHe/zinit";
                  license = nixpkgs.lib.licenses.mit;
                  platforms = systems;
                  mainProgram = "zinit";
                };
              }
              ''
                tar -xzf ${
                  pkgs.fetchurl {
                    url = "https://github.com/ComixHe/zinit/releases/download/${release}/${tarball}";
                    hash = sources.${system}.${mode};
                  }
                } -C /tmp

                mkdir -p $out/bin $out/share/licenses/zinit $out/share/doc/zinit
                install -m 0755 "/tmp/${unpacked}/zinit" $out/bin/zinit
                install -m 0644 "/tmp/${unpacked}/LICENSE" $out/share/licenses/zinit/LICENSE
                install -m 0644 "/tmp/${unpacked}/README.md" $out/share/doc/zinit/README.md
              '';
        in
        {
          zinit = mkPackage "small";
          zinit-safe = mkPackage "safe";
          default = mkPackage "small";
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          runs =
            name:
            pkgs.runCommand "${name}-runs" { } ''
              ${self.packages.${system}.${name}}/bin/zinit --version | grep -qF "${version}"
              touch $out
            '';
        in
        {
          zinit-runs = runs "zinit";
          zinit-safe-runs = runs "zinit-safe";
        }
      );

      overlays.default = final: prev: {
        zinit = self.packages.${final.stdenv.hostPlatform.system}.zinit;
        zinit-safe = self.packages.${final.stdenv.hostPlatform.system}.zinit-safe;
      };
    };
}
