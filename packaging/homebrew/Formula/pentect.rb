class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.26"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.26/pentect-macos-aarch64"
      sha256 "96731c04f06115bee7855a8b7adcfc9817b500815a3d528b159bd6589ec88dc9"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.26/pentect-macos-x86_64"
      sha256 "bf8d11ae38c44e55440822dece4861213ab134812c5dd6c7344af9bb3465cbc5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.26/pentect-linux-aarch64"
      sha256 "55bcae638f8f2e5c381873ea0bbf9742c35194d692cfc59152d7b2ef410e37ba"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.26/pentect-linux-x86_64"
      sha256 "0961077e77ff97434d27871f47f00f3b4475cf2e4c723690b2f5d59f353af46a"
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
