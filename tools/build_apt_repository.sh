#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: build_apt_repository.sh DEB_DIR OUTPUT_DIR PUBLIC_KEY SIGNING_FINGERPRINT" >&2
  exit 2
fi

deb_dir=$1
output_dir=$2
public_key=$3
fingerprint=$4
command -v dpkg-scanpackages >/dev/null 2>&1 || { echo "dpkg-scanpackages is required" >&2; exit 2; }
command -v apt-ftparchive >/dev/null 2>&1 || { echo "apt-ftparchive is required" >&2; exit 2; }
command -v gpg >/dev/null 2>&1 || { echo "gpg is required" >&2; exit 2; }
test -f "$public_key" || { echo "missing public key: $public_key" >&2; exit 2; }
public_fingerprint=$(gpg --batch --with-colons --show-keys "$public_key" |
  awk -F: '$1 == "fpr" { print $10; exit }')
if [ "$public_fingerprint" != "$fingerprint" ]; then
  echo "public key does not match signing fingerprint" >&2
  exit 2
fi

rm -rf "$output_dir"
pool="$output_dir/apt/pool/main/p/pentect"
dist="$output_dir/apt/dists/stable"
mkdir -p "$pool" "$dist"
find "$deb_dir" -maxdepth 1 -type f -name 'pentect_*.deb' -exec cp {} "$pool/" \;
test -n "$(find "$pool" -type f -name '*.deb' -print -quit)" || { echo "no Debian packages found" >&2; exit 2; }

architectures=""
for architecture in amd64 arm64; do
  if find "$pool" -type f -name "*_${architecture}.deb" -print -quit | grep -q .; then
    architectures="${architectures}${architectures:+ }${architecture}"
    packages="$dist/main/binary-$architecture"
    mkdir -p "$packages"
    (cd "$output_dir/apt" && dpkg-scanpackages --multiversion --arch "$architecture" pool /dev/null) > "$packages/Packages"
    gzip -9n -c "$packages/Packages" > "$packages/Packages.gz"
  fi
done

cat > "$output_dir/apt/release.conf" <<EOF
APT::FTPArchive::Release::Origin "Pentect";
APT::FTPArchive::Release::Label "Pentect";
APT::FTPArchive::Release::Suite "stable";
APT::FTPArchive::Release::Codename "stable";
APT::FTPArchive::Release::Architectures "$architectures";
APT::FTPArchive::Release::Components "main";
APT::FTPArchive::Release::Description "Pentect packages";
EOF
(cd "$output_dir/apt" && apt-ftparchive -c release.conf release dists/stable) > "$dist/Release"
gpg --batch --yes --local-user "$fingerprint" --clearsign --output "$dist/InRelease" "$dist/Release"
gpg --batch --yes --local-user "$fingerprint" --armor --detach-sign --output "$dist/Release.gpg" "$dist/Release"
install -m 0644 "$public_key" "$output_dir/apt/pentect-archive-keyring.asc"
cat > "$output_dir/apt/pentect.sources" <<'EOF'
Types: deb
URIs: https://pentect.dev/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/pentect-archive-keyring.asc
EOF
rm "$output_dir/apt/release.conf"
