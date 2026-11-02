class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.97"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.97/pentect-macos-aarch64"
      sha256 "bfc065c2b0d417f763795bccd3886b75243da6672b1d97c1239a569ae906b781"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.97/pentect-macos-x86_64"
      sha256 "83c4e6348c826da75dec04e4c9a155b4522487cb8bb2580189f19a6aecad386a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.97/pentect-linux-aarch64"
      sha256 "ce6d0b836d27342973d6976e49885ca2be67fb672d520cdab3e47d0df096aca6"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.97/pentect-linux-x86_64"
      sha256 "642c680307eeb9615d5aae9e278af1721c2d057ff85e5c94ac3947be20ff50ec"
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
