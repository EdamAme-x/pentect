class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.16"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.16/pentect-macos-aarch64"
      sha256 "1b0108b8c674211ded51ce76c3b258685b391b7fe139691929699081ce168c26"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.16/pentect-macos-x86_64"
      sha256 "9a6b9abce5c2eb606d33b4a2d7719d679a5ecb656b23b87f6753d4ef215ec6e2"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.16/pentect-linux-aarch64"
      sha256 "de8e44dfaa56035cc6f86ca503dad25d9a5620344a1b3e09bdf4de34544cab98"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.16/pentect-linux-x86_64"
      sha256 "a4c492a507c2042a13087adbe6c6219064e2d6f0eefc2b0f7eb7daf46599a620"
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
