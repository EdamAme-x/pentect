class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.79"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.79/pentect-macos-aarch64"
      sha256 "cbfd5bea7727373487a299b8b255657ac87318d538d1f5f232b68a6e862a09ca"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.79/pentect-macos-x86_64"
      sha256 "8c8bc23eecc26c6a779bc5db902b43ce0948184a85596c3abf08edcdbd6ee484"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.79/pentect-linux-aarch64"
      sha256 "fec22afe9d9713d29f9b1122e7daf9cc459462ed8c891ff19046b6ed355a0a6c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.79/pentect-linux-x86_64"
      sha256 "a91ad1977ac45785acebd2b462934847790953520d83f251fa4f79d8f51acebd"
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
