class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.43"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.43/pentect-macos-aarch64"
      sha256 "70ebd754bebc037b6f0a62f41fe78adfecdb780dd99fd6c8a1b2dc3598b1c019"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.43/pentect-macos-x86_64"
      sha256 "97e8ee97a9c69a1822d906f8fc8d7973fd68c4564e482ad29d90678163fba74f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.43/pentect-linux-aarch64"
      sha256 "0fb3f4ca234e7a030b81c71d787702d923591d291eede92f1afe5c980a68a642"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.43/pentect-linux-x86_64"
      sha256 "c33c4a39673f6d3ba88d352b169e0b03d57799e68e94a6ef991a88456cd9c937"
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
