{pkgs, ...}: {
  packages = [pkgs.cargo-machete pkgs.cocogitto pkgs.git];

  languages = {
    rust.enable = true;
  };

  services = {
    redis.enable = true;
  };

  pre-commit.hooks = {
    # Nix

    alejandra.enable = true;

    # Git

    cocogitto = {
      enable = true;
      entry = "cog verify --file .git/COMMIT_EDITMSG";
      stages = ["commit-msg"];
      pass_filenames = false;
    };

    # Rust

    cargo-check.enable = true;
    rustfmt.enable = true;
    clippy.enable = true;

    test = {
      enable = true;
      entry = "cargo test --all-features";
      pass_filenames = false;
      stages = ["pre-push"];
    };
  };
}
