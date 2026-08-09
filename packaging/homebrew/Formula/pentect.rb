class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.29"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.29/pentect-macos-aarch64"
      sha256 "704c1bc52a861116c91479ab8fc0d91b3631472c83f0642af0d488de6695da3d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.29/pentect-macos-x86_64"
      sha256 "78e309b19d1a3f4f1d1f3502d92427997b70b034cf4d2498cc24d25aedb275d2"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.29/pentect-linux-aarch64"
      sha256 "4a6f457e7260f3d07a39d47ae7a237e83f83f143c68499e50bc5168b6ad23585"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.29/pentect-linux-x86_64"
      sha256 "e5d91d7729408175dc526c44e6b65cc714124ba4bc312933c7d0b2a63dd4cdc7"
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
