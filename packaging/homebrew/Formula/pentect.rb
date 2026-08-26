class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.58"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.58/pentect-macos-aarch64"
      sha256 "12b2b4b5aa71862e14d11bdbc8aa9d04c230278c2eee96cf9a7f1e033e25843c"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.58/pentect-macos-x86_64"
      sha256 "653f8b69a36128e89acf98efc6fcb0054af7e6622054e80e6f0864867f050a06"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.58/pentect-linux-aarch64"
      sha256 "51d8770952548d5357b0959bbfd694e02f86bae6694c64e0f42a4d1b0a5a72bc"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.58/pentect-linux-x86_64"
      sha256 "31c1d6b11be04538fe9ea8b1212c4b9c9c6bc06bd1b6068cf96afdf85d7804c7"
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
