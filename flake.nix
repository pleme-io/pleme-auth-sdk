{
  description = "Authentication SDK for Nexus products";

  inputs = {
    nixpkgs.follows = "substrate/nixpkgs";
    dream2nix = {
      url = "github:nix-community/dream2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, dream2nix, substrate, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      eachSystem = f: nixpkgs.lib.genAttrs systems f;
      mkOutputs = system:
        let
          tsLibrary = import "${substrate}/lib/typescript-library.nix" {
            inherit system nixpkgs dream2nix;
          };
        in
        tsLibrary {
          name = "pleme-auth-sdk";
          src = self;
        };
    in
    {
      packages = eachSystem (system: (mkOutputs system).packages);
      devShells = eachSystem (system: (mkOutputs system).devShells);
      apps = eachSystem (system: (mkOutputs system).apps);
    };
}
