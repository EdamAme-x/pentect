class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.64"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.64/pentect-macos-aarch64"
      sha256 "e7fb2d3f93ede4fdd2e258688dd3ce083daf47528048e157ddb87ef5ec02e8d9"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.64/pentect-macos-x86_64"
      sha256 "cd5c3c5972530952b3e96447b021287b8b90c03c409f07dc5680f578730c0b62"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.64/pentect-linux-aarch64"
      sha256 "2f1df691b09bb85242ffe38d375e6986c4f36806e95132375fa97decf9f6370f"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.64/pentect-linux-x86_64"
      sha256 "fdb868104854464e8b51c5e9ee4cc7e9fed9a87c3f0155b37c3c788f8dbd4e1c"
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
