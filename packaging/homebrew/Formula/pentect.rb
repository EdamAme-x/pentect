class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.78"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.78/pentect-macos-aarch64"
      sha256 "0a2d0395b5ae76c1589f19f91b28603f568a714c29f87092434114c0d80831bc"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.78/pentect-macos-x86_64"
      sha256 "cb30f3f3f1c4ce8b1ab4b3e471b260bc9679257cf1af14fb7753d7f90650fea9"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.78/pentect-linux-aarch64"
      sha256 "b2846aa9d7fb9564b980d2e027b049b3abf1600214db84fac40305b9a6409585"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.78/pentect-linux-x86_64"
      sha256 "66728b6574babaa10f6a4a6ae83900bfb8163590fab92f143e2f84f867e9dbad"
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
