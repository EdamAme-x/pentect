class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.25"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.25/pentect-macos-aarch64"
      sha256 "fea374ec50c0e90b29ab0a9ecad521564023cf7361aee7d9c32f6dd8bf0be5c7"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.25/pentect-macos-x86_64"
      sha256 "d4687c44a8d18bfc9d577538f903aee48f47171fb6c61ac4c320a973e017a779"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.25/pentect-linux-aarch64"
      sha256 "b2770b33e6f987f79c412d399adaf8480cd2e52782c786b56196d5800b5ec1bc"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.25/pentect-linux-x86_64"
      sha256 "ff57fece6ef80f7ce71252f19944e92dd29a930231173a746cad116fc5280b84"
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
