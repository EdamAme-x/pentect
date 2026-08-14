class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.31"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.31/pentect-macos-aarch64"
      sha256 "d8528ac477a7237267670972579e1f4af8a9deb958b0b8fe5542a7aecbc992ef"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.31/pentect-macos-x86_64"
      sha256 "9294e8f5bde97f04f1711615a4daac360ad560f6825d0ffd8bf056ccc4155e44"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.31/pentect-linux-aarch64"
      sha256 "13794c3e2d215f8e9f1e88e700a1ae6185cb81643264aee9b273e6ced89b731c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.31/pentect-linux-x86_64"
      sha256 "8a293b54aec0873742607376fe14965040f97bd6bd16fbff80fecfb6a6454597"
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
