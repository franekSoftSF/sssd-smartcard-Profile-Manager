#!/usr/bin/env bash
#
# build-tarball.sh -- produce a self-contained release archive.
#
# The archive holds the Python package, the setup script, the installer, the
# example profiles, the documentation and the test lab. It carries no vendored
# dependencies: install.sh uses the distribution's own python3-cryptography and
# python3-yaml, so the archive stays small and nothing shadows a system package.
#
# Runs anywhere with bash and tar, including Git Bash on Windows.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"

VERSION="$(
    sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$ROOT/src/sssd_smartcard/__init__.py" | head -1
)"
[[ -n "$VERSION" ]] || { echo "could not read __version__ from src/sssd_smartcard/__init__.py" >&2; exit 1; }

NAME="sssd-smartcard-$VERSION"
STAGE="$DIST/$NAME"
TARBALL="$DIST/$NAME.tar.gz"

printf 'building %s\n' "$NAME"

rm -rf "$STAGE" "$TARBALL" "$TARBALL.sha256"
mkdir -p "$STAGE"

# --- what goes in -----------------------------------------------------------
copy() {
    local src="$1" dest="$2"
    if [[ -d "$ROOT/$src" ]]; then
        mkdir -p "$STAGE/$(dirname "$dest")"
        cp -a "$ROOT/$src" "$STAGE/$dest"
    elif [[ -f "$ROOT/$src" ]]; then
        mkdir -p "$STAGE/$(dirname "$dest")"
        cp -a "$ROOT/$src" "$STAGE/$dest"
    else
        echo "  missing (skipped): $src" >&2
    fi
}

copy src                 src
copy man                 man
copy debian              debian
copy packaging           packaging
copy scripts             scripts
copy profiles            profiles
copy docs                docs
copy lab                 lab
copy tests               tests
copy install.sh          install.sh
copy Makefile            Makefile
copy README.md           README.md
copy pyproject.toml      pyproject.toml

# --- clean the stage --------------------------------------------------------
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.py[co]' -delete 2>/dev/null || true
find "$STAGE" -name '.pytest_cache' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# --- executable bits -------------------------------------------------------
chmod 0755 "$STAGE/install.sh" 2>/dev/null || true
find "$STAGE/scripts" "$STAGE/lab" -name '*.sh' -exec chmod 0755 {} + 2>/dev/null || true

# --- metadata --------------------------------------------------------------
printf '%s\n' "$VERSION" >"$STAGE/VERSION"
cat >"$STAGE/INSTALL.txt" <<EOF
sssd-smartcard $VERSION

QUICK START

  tar xzf $NAME.tar.gz
  cd $NAME
  sudo ./install.sh

  # then, on a domain-joined host with a card in the reader:
  sudo sssd-smartcard-setup --dry-run --test-user user@domain-a.local \\
       --ca /root/pki/root-ca.pem --ca /root/pki/issuing-ca.pem

  # when the dry run looks right, drop --dry-run and add --yes

WHAT install.sh DOES
  Installs the Python package to /opt/sssd-smartcard, the CLI to
  /usr/local/bin/sssd-smartcard, the setup script to
  /usr/local/sbin/sssd-smartcard-setup, and example profiles to
  /etc/sssd-smartcard/profiles. Dependencies come from your distribution
  (python3-cryptography, python3-yaml). Nothing is downloaded from the internet.
  It never touches sssd.conf, the CA trust store or PAM.

  Undo with: sudo ./install.sh --uninstall

TEST LAB (no hardware, no real domain needed)
  lab/ holds a Vagrant environment: a Samba AD domain controller plus an Ubuntu
  client whose "smart card" is a SoftHSM2 token. See lab/README.md.

BUILD A .deb INSTEAD (Ubuntu / Debian)
  bash packaging/build-deb.sh          # needs only dpkg-deb, no root
  sudo apt install ./dist/sssd-smartcard_<version>_all.deb

  The canonical route, if you have debhelper:
  dpkg-buildpackage -b -us -uc

REQUIREMENTS
  Python 3.10+, bash 4.4+, and on the target host: sssd, sssd-tools.
  The setup script installs the rest itself.
EOF

# --- pack ------------------------------------------------------------------
tar -czf "$TARBALL" -C "$DIST" "$NAME"
rm -rf "$STAGE"

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$DIST" && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256" )
elif command -v shasum >/dev/null 2>&1; then
    ( cd "$DIST" && shasum -a 256 "$NAME.tar.gz" >"$NAME.tar.gz.sha256" )
fi

SIZE="$(wc -c <"$TARBALL" | tr -d ' ')"
printf '\n%s\n' "built: $TARBALL ($(( SIZE / 1024 )) KiB)"
[[ -f "$TARBALL.sha256" ]] && printf '%s\n' "sha256: $(cat "$TARBALL.sha256")"
printf '\ncontents:\n'
tar -tzf "$TARBALL" | sed 's/^/  /' | head -30
printf '  ... %s entries total\n' "$(tar -tzf "$TARBALL" | wc -l | tr -d ' ')"
