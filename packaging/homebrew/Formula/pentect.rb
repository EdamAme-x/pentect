class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.93"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.93/pentect-macos-aarch64"
      sha256 "0a284f20832578da83a0e4d02230a6fb50850eb124ac46f19a3646a3acceb2ac"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.93/pentect-macos-x86_64"
      sha256 "366f1b9a4743ab072d368f59dba6c5200a392eb38a222ab183bee34edbfa519e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.93/pentect-linux-aarch64"
      sha256 "dddb3fd7d7268783a5046dcff5b1d318f940940efd2cd4503484b0469f6320ee"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.93/pentect-linux-x86_64"
      sha256 "ac0c73027fb11ce78077ed27f9ca9d2dc976d40146535b6b1e1e4aad4f893abe"
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
