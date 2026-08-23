{
  description = "electric-eye - Linux activity and anomaly monitor";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          rustc
          cargo
          rustfmt
          clippy

          rustup

          clang
          llvm
          libclang
          lld

          pkg-config

          bpftools
          elfutils

          sqlite
          systemd

          just
          jq

          cargo-nextest
        ];

        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

        shellHook = ''
          echo "electric-eye development environment"
          echo "Rust: $(rustc --version)"
          echo "clang: $(clang --version | head -1)"
        '';
      };
    };
}
