class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.61"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.61/pentect-macos-aarch64"
      sha256 "2faf65bdeec66c195b7e53ad5839faf2ca207eeadaea1dd94ee66347f7d0e151"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.61/pentect-macos-x86_64"
      sha256 "149d832e8c81d6d0a544df6764777f7b34f8780a7c010bb762471b0a7be16500"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.61/pentect-linux-aarch64"
      sha256 "dda32c7471998c83a209163322a7abb4baae555a272ba7af31f5166503e725f7"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.61/pentect-linux-x86_64"
      sha256 "b99eeeb82d16aedfeb0828522acec253f388b3d0d46e03ec833ef18b4f6bbe35"
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
