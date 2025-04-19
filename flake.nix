{
  description = "Rust environment for fswatcher";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" "llvm-tools-preview" "rust-analyzer" ];
        };


        devPackages = with pkgs; [
          pre-commit
        ];

      in {
        devShells.default = pkgs.mkShell {
          name = "dev";
          buildInputs = [ rustToolchain ] ++  devPackages;
        };
      });
}
