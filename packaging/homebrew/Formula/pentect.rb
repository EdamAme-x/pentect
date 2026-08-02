class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.15"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.15/pentect-macos-aarch64"
      sha256 "ffb772a94ff46f9cf5d37fe27e527d52d04cc92cb4ae3d74d5fdc5a4e799df38"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.15/pentect-macos-x86_64"
      sha256 "763fb530e23cde179b5f70392fc4586480a55182f5495fd0fb1c7a88be1e2f91"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.15/pentect-linux-aarch64"
      sha256 "bb970132fabbeef6c78ab6e6fe0c22281a30ce8a2150b4a5f8b1f9877d10129f"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.15/pentect-linux-x86_64"
      sha256 "f434fb48b4d84ee41556146dcd92ab1e53d49d84c5d98f46df93e3508ba79627"
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
