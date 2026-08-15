class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.33"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.33/pentect-macos-aarch64"
      sha256 "bd548b3b85354cb3ec6b3be07613fdd8f1f20e4c3e7e2f9d76f5ddca6ed4b7f4"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.33/pentect-macos-x86_64"
      sha256 "3cf8483a11ad7cbdc9dbecf0fa727c7f8e559dd96702a7e60cd0f27bf69583e4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.33/pentect-linux-aarch64"
      sha256 "5136537476198d0cc450be407661cb712353bd1f9013fb01edeb273acfee3d8e"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.33/pentect-linux-x86_64"
      sha256 "ac809cdc71c4b47c30ca3c29d5c59d4dfdb14d7b5ebca8aa0a8ef106a7fff031"
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
