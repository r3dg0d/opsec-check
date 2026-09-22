{
  description = "opsec-check — umbrella privacy/security audit CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        opsec-check = pkgs.rustPlatform.buildRustPackage {
          pname = "opsec-check";
          version = "0.1.0";
          src = ./.;
          cargoLock = { lockFile = ./Cargo.lock; };
          meta = with pkgs.lib; {
            description = "Umbrella privacy/security audit CLI";
            license = licenses.mit;
            maintainers = [ ];
            mainProgram = "opsec-check";
          };
        };
      in {
        packages.default = opsec-check;
        packages.opsec-check = opsec-check;
        apps.default = flake-utils.lib.mkApp { drv = opsec-check; };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ rustc cargo rustfmt clippy pkg-config ];
        };
      });
}
