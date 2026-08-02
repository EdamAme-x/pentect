class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.14"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.14/pentect-macos-aarch64"
      sha256 "dfbdf9b3474c88aa96fcd8c4f6e6e4b735a338ef86428275c5c3658476ab5ed8"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.14/pentect-macos-x86_64"
      sha256 "c1276893f544eb355140553ba80ead8eacc228bd49cb6efa262cf870b790e43f"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.14/pentect-linux-x86_64"
      sha256 "3cce25b1d9aee543e8bad8b7c217d0685f4bcb50f3de865cb8f70dd003785c37"
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
