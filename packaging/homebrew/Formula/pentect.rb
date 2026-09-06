class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.77"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.77/pentect-macos-aarch64"
      sha256 "b59d63bf050707c19b90d0c6e09da1730edea448fae3a9a3daa093fd86cddf7d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.77/pentect-macos-x86_64"
      sha256 "9e457a5c52a32ec4c52460d5568fa751452f33ef61f3d992abefc64e3ca2ccb4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.77/pentect-linux-aarch64"
      sha256 "4e0ca00331221c67ced5cad59536400ad1e2a430ac97d3c2472c6808eaac2106"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.77/pentect-linux-x86_64"
      sha256 "f72bcc49b2f767390c047840fb4d6ed86b83a195c98f457c523221b7a7f71e3e"
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
