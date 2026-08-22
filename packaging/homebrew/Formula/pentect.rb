class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.53"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.53/pentect-macos-aarch64"
      sha256 "c06675dde8bc1bcf2d96caae4a26d16c80dd4c2c8ee8faaad18e4e2690b2e73d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.53/pentect-macos-x86_64"
      sha256 "bbb333d51e017f410d78939309af58cc839aeceff90290be10cb8276695a66e7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.53/pentect-linux-aarch64"
      sha256 "ee461670d5ad5091fee201239cd26770a8f58fc8a425814bbabf6fa0c81f5e85"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.53/pentect-linux-x86_64"
      sha256 "ec07cff817cc99f9052b8ab2f59c7eb00f5acd9c8a08419d2c5f6c7dd5bf14a6"
    end
  end

  def install
    binary = Dir["pentect-*"].first
    bin.install binary => "pentect"
    (bin/".pentect-managed-install.json").write <<~JSON
      {"version":1,"manager":"homebrew","update":"brew upgrade EdamAme-x/pentect/pentect","uninstall":"brew uninstall EdamAme-x/pentect/pentect"}
    JSON
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pentect version")
  end
end
