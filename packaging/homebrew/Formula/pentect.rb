class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.17"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.17/pentect-macos-aarch64"
      sha256 "65a4412fc7bc358af4d754d497aa7439b013cd156f55e2c2303140e0716fd98a"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.17/pentect-macos-x86_64"
      sha256 "3efa9a767327a537fe0aacf7679411359a86cefcba73726cc6cff538c4023175"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.17/pentect-linux-aarch64"
      sha256 "f6f37cb25f236161a578a34ecd9f0be0c3da2ee186227a65402c2e122072659d"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.17/pentect-linux-x86_64"
      sha256 "3f3be75e64e35ed0d1f927619b4158b905b800e6bb5129d23e291d658842eda3"
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
