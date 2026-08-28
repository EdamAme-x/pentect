class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.68"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.68/pentect-macos-aarch64"
      sha256 "63055450fa7f1e71bc29f325f2f8058836fc7374db8b81e0aae474b0a6a5ae6a"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.68/pentect-macos-x86_64"
      sha256 "b33edd251e06549b669bc01b7644b42e87e77819b4a42b80e07675e3638414aa"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.68/pentect-linux-aarch64"
      sha256 "aeef1a74b012cd4397b88d1ab2348012ff81eb270511437ca7edbab9efeadac5"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.68/pentect-linux-x86_64"
      sha256 "3d4401afe42dd5524fdebfa471a95aa8c660b9218ccd0d54ce6ddaa608e3a5e5"
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
