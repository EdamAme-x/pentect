class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.74"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.74/pentect-macos-aarch64"
      sha256 "5112cbf40d43b69f1b5b8389cc08129fc173df5f60538dfcdb58387d4017880c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.74/pentect-macos-x86_64"
      sha256 "c92395a411a69a4a8703c6235d4570fd28c7faf60007d0f4c0e6c4d24de49e70"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.74/pentect-linux-aarch64"
      sha256 "6e746f342ce32ccfc0df9ea58a354c798f9cee79471250bfe8657e613f2f288d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.74/pentect-linux-x86_64"
      sha256 "378ebd67c754c1172cac718deec96f6984070a0e02b53b0f50a90250490c96ef"
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
