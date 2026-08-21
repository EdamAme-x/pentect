class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.51"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.51/pentect-macos-aarch64"
      sha256 "866bd95fcd9676b21ef834caf47f68cc8edb2c2355afbb94209adc4cee088f37"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.51/pentect-macos-x86_64"
      sha256 "6cda4ce138a7842e0e6341129da11e87091bfff634e7383888d3331469e6044c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.51/pentect-linux-aarch64"
      sha256 "f3ec57dcc7609e582236c5c474af828c7dbf98e777ca4a45c3e64d1072bbce33"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.51/pentect-linux-x86_64"
      sha256 "5f43e449b59eabcc373e05571fbaccb6581ba2120f316b9ddbfb4f400681bf98"
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
