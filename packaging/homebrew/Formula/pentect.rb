class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.52"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.52/pentect-macos-aarch64"
      sha256 "9d5f4bf59b790f96bfeaab0c73ece74f36a96947b57c3c70db7fea381f58110b"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.52/pentect-macos-x86_64"
      sha256 "aa151ccc9dabc5522b25494621ac6e5d8896fbf6cfcb6b5c92f6ec0bb9c9a99a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.52/pentect-linux-aarch64"
      sha256 "74e74484fe5a6f495e620397b972eff6e47100b4e036c114edf1845cbf8a604e"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.52/pentect-linux-x86_64"
      sha256 "6fbb50e08f1bc55a97bd29d5561be4c15f4beafd46a8efa1c6b334c5baf25699"
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
