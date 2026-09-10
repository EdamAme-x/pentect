class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.83"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.83/pentect-macos-aarch64"
      sha256 "437b6439a141137c700bda5c5173e75241a349ee025ebbe1f241ba5bc35ec024"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.83/pentect-macos-x86_64"
      sha256 "e89d1e26824d72ea0c3385f28414d7f7dd5646bb52cfb10dd67ca5c8729b7974"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.83/pentect-linux-aarch64"
      sha256 "ad30a2167cb8585133e7e45d3c88af3ca9d9fa6697393b0cdc118e7a3bdde22d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.83/pentect-linux-x86_64"
      sha256 "f4e826ae529f387723adddae6686946bd943874abda652b5f59ba74433459f6d"
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
