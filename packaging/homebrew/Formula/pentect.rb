class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.71"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.71/pentect-macos-aarch64"
      sha256 "b18340dee2609783c9901b2e12a48964f954af94102a2fc455c53ef61141bdbf"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.71/pentect-macos-x86_64"
      sha256 "e764c93e3b2f44cab2f7f30ddc2d3cf1890d36785aa2dc5267224708c34dd66c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.71/pentect-linux-aarch64"
      sha256 "13eb933e95a6067d58fc391010f974e6b0a6ca8d80986c05ab8778b4aa1e7e49"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.71/pentect-linux-x86_64"
      sha256 "e4100f0d54abe6246e9bce7f78ef72ea05526b33559340a43a953347ca938376"
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
