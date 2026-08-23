class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.55"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.55/pentect-macos-aarch64"
      sha256 "3b2d352074bf1e76d09d77bcdd361ff3fe706fe1a69cef3154ec5c6c3df48bdd"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.55/pentect-macos-x86_64"
      sha256 "24f17a55c615ae12f4413f4b4074e6d21a187615f91aef879d38c1b49745a993"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.55/pentect-linux-aarch64"
      sha256 "622d18974e7956ec5cf473c231401b9ff265eb110593c84d739d3028f84fb32f"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.55/pentect-linux-x86_64"
      sha256 "9476c8413b781ed2301f21b8778bfe6c804c3be084ad17af1353ae361ae27ab5"
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
