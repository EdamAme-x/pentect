class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.94"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.94/pentect-macos-aarch64"
      sha256 "8c514fe68059c449d2b4c61764eafee71c7b81062fd3daf0915bc2fcb78a4bfe"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.94/pentect-macos-x86_64"
      sha256 "959291bb4a03ab8bb31474b252f7150abaa3b3bd14e247dbe66ba29e554fad44"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.94/pentect-linux-aarch64"
      sha256 "e3281b73c5746805603f94d7e8fd130d732b514777e75761e180a3d3cd368936"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.94/pentect-linux-x86_64"
      sha256 "6e9436418be794b50a055496b53af4fd069d5d3e3d784783bd36a51f71d5e55a"
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
