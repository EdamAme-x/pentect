from pathlib import Path


release = Path(".github/workflows/release.yml").read_text()
publish_pi = Path(".github/workflows/publish-pi.yml").read_text()

publish_start = release.index("  npm-publish:\n")
readiness_start = release.index("  npm-readiness:\n")
next_job = release.index("\n  package-metadata:\n", readiness_start)
publish = release[publish_start:readiness_start]
readiness = release[readiness_start:next_job]

assert "npm publish --access public" in publish
assert "Trigger matching Pi extension release" not in publish
assert "needs: npm-publish" in readiness
wait = 'tools/wait_for_npm_version.sh pentect "${GITHUB_REF_NAME#v}" 30 5'
assert wait in readiness
assert readiness.index(wait) < readiness.index("gh workflow run publish-pi.yml")
assert 'tools/wait_for_npm_version.sh @pentect/pi "$version" 30 5' in readiness
assert "needs: [lifecycle, apt-repository, npm-readiness]" in release
assert '../../tools/wait_for_npm_version.sh pentect "$version" 30 5' in publish_pi
pi_readiness = publish_pi.index("  readiness:\n")
assert "needs: publish" in publish_pi[pi_readiness:]
assert 'tools/wait_for_npm_version.sh @pentect/pi "$version" 30 5' in publish_pi[pi_readiness:]
