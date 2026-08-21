class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.49"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.49/pentect-macos-aarch64"
      sha256 "288abdb7da99c430ae0d27e9cc3049ac9a81a26625264df29f571d564424bf5e"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.49/pentect-macos-x86_64"
      sha256 "ae81ce41f410b6751f4ed394051c771f1b9d5ef42a142f5c9f9165a2bf3f823a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.49/pentect-linux-aarch64"
      sha256 "c599468fbde9398789a3c352c55d86206e28719ac42e1ffd70ec8cc359b80792"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.49/pentect-linux-x86_64"
      sha256 "4e06ece3769173b968e8cccd4242d4d489cb0a96d585512420afeb6ab9c8c133"
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
