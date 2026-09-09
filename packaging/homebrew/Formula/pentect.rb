class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.82"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.82/pentect-macos-aarch64"
      sha256 "d6a588dbd4a44845f8a0bf275cae5a7291cb12485981f7686dff8c421213cf39"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.82/pentect-macos-x86_64"
      sha256 "076217c42b5950e0b086e4d42920af2f45bfc5a0acca277238fc3ee83dcff615"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.82/pentect-linux-aarch64"
      sha256 "f6c1cb9d181eeb375c51ad8ad5816b04c4df554dd405345b57be6dc80020d730"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.82/pentect-linux-x86_64"
      sha256 "5d533f56145b28012ab934cd59a022b78dcad0d9fd7de5f0487a9517f24a0d6b"
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
