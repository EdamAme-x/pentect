class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.73"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.73/pentect-macos-aarch64"
      sha256 "2fb87aa208898f7502657d000725fd0b9493743a7a5db9dbe27f355a63489678"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.73/pentect-macos-x86_64"
      sha256 "854f9225c4d0ab540df6374480c96936a72f5f96a5fe876a3544d6bd2edaa2ec"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.73/pentect-linux-aarch64"
      sha256 "c554d03702811fc57b70dc36e8d446df5a158fc781b3f26fe6d8d0f7fd23cc96"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.73/pentect-linux-x86_64"
      sha256 "ec246985fe9edcb60fcb09c891cd1e0cafe999a8f173ca7199b5457565fa6f35"
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
