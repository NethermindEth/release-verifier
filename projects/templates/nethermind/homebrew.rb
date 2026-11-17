class Nethermind < Formula
  desc "A robust execution client for Ethereum node operators."
  homepage "https://nethermind.io/nethermind-client"
  license "LGPL-3.0-only"
  version "{{version}}"
  
  case
  when OS.mac? && Hardware::CPU.intel?
    url "{{url:macos-x64}}"
    sha256 "{{sha256:macos-x64}}"
  when OS.mac? && Hardware::CPU.arm?
    url "{{url:macos-arm64}}"
    sha256 "{{sha256:macos-arm64}}"
  else
    odie "Platform not supported"
  end

  def install
    bin.install Dir['./chainspec']
    bin.install Dir['./configs']
    bin.install Dir['./Data']
    bin.install Dir['./keystore']
    bin.install Dir['./plugins']
    bin.install Dir['./nethermind']
    bin.install Dir['./NLog.config']
  end

  test do
    system "false"
  end
end
