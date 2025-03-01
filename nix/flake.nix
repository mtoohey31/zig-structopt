{
  description = "zig-structopt";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) mkShellNoCC zig zls;
      in
      {
        devShells.default = mkShellNoCC { packages = [ zig zls ]; };
      });
}
