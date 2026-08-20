class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.38"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.38/pentect-macos-aarch64"
      sha256 "70b7f2f22b177c50c8c5e1e125a632ac088bc0821c43f4825c44a9db420c1c07"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.38/pentect-macos-x86_64"
      sha256 "4eb3e3b29a193f33c1cac4c75a5fe165609a7360bcdf25f601e8919741dac5e8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.38/pentect-linux-aarch64"
      sha256 "78939d9b083f096d497d7fd85020d3a66ed49691067dc9ea33dc2c98a6041334"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.38/pentect-linux-x86_64"
      sha256 "91a9a1a036d9cbd7cc23a3088450db77764456141c4a99bb9d47cb0547121f55"
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
