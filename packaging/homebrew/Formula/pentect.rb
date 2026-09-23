class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.92"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.92/pentect-macos-aarch64"
      sha256 "e6c0da59e424515255f10c643918ab39eec320cd7e90a5fbd677677cb19f6033"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.92/pentect-macos-x86_64"
      sha256 "9df756fbccb9f6c062c0f9574e77406b464b486ddf929d99c567c522fad00113"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.92/pentect-linux-aarch64"
      sha256 "dbab99cf5a1325ebc49a1cffd216f7b0cff5e576952906221bbb45dd0b6137d9"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.92/pentect-linux-x86_64"
      sha256 "234e0374814d5106c8117f0791eff72289fd04e41e2218d8d039ceb54b7dce79"
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
