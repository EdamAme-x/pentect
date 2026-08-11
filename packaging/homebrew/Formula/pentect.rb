class Pentect < Formula
  desc "Local secret masking boundary for AI agents"
  homepage "https://github.com/EdamAme-x/pentect"
  version "0.0.30"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.30/pentect-macos-aarch64"
      sha256 "54281d7a44593bdd3cdf26936ff05f86d735de5b9345cc4b0a58554f10dea9cd"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.30/pentect-macos-x86_64"
      sha256 "33cb63936da2be32cc336c283446515abc22451a3f2d9ad1547e8fa77577c829"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.30/pentect-linux-aarch64"
      sha256 "f7737bfee21ae886b9724c115d271c119b3e9b15c9bcdd4abd4a986c4178c041"
    end
    on_intel do
      url "https://github.com/EdamAme-x/pentect/releases/download/v0.0.30/pentect-linux-x86_64"
      sha256 "c97330f8812103a9e40037bdce3d14795d6dd59f6428b0213da7df0485c85302"
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
