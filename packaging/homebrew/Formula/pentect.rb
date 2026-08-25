class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.57"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.57/pentect-macos-aarch64"
      sha256 "fe2a3d7ec979e48ae37be8895f1ad779abf1470628d117dcc2e05aaa01c21806"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.57/pentect-macos-x86_64"
      sha256 "145136c8b9ddabf7615dd5a8657814931e07724f7b67e242469fed234b207546"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.57/pentect-linux-aarch64"
      sha256 "4e754d103727f5304770508974dc4f72bebd0e9316d0de94525960292f07de48"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.57/pentect-linux-x86_64"
      sha256 "9bbffa3ff595069f8ed3ce3491c2adfa64c4c028c9f2c87478f1d492ef94b105"
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
