#!/usr/bin/env bash
# Verifies the PGP signature of every artifact file in a Maven repository
# directory (docs/releasing.md, "Signing"). Called by the verifyReleaseSignatures
# and verifyRemoteSignatures Gradle tasks:
#
#   verify-signatures.sh <repository dir> <public key: armored file or key ID>
#
# Only the PUBLIC key is used: a key ID is exported (public part only) from the
# caller's keyring into a temporary GNUPGHOME, which is removed afterwards.
# Every artifact file (not metadata, signatures or checksums) must have a .asc
# that verifies with that key; zero signatures is a failure.
set -euo pipefail

repo="${1:?repository directory}"
key="${2:?public key file or key ID}"
[ -d "$repo" ] || { echo "no repository directory $repo" >&2; exit 1; }

home="$(mktemp -d)"
trap 'gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; rm -rf "$home"' EXIT
chmod 700 "$home"

if [ -f "$key" ]; then
    gpg --homedir "$home" --batch --quiet --import "$key"
else
    gpg --batch --armor --export "$key" > "$home/public.asc"
    [ -s "$home/public.asc" ] || { echo "no public key $key in the keyring" >&2; exit 1; }
    gpg --homedir "$home" --batch --quiet --import "$home/public.asc"
fi
if gpg --homedir "$home" --batch --list-secret-keys 2>/dev/null | grep -q .; then
    echo "refusing to verify with a secret key in the verification keyring" >&2
    exit 1
fi

verified=0
failed=0
missing=0
while IFS= read -r -d '' file; do
    case "$file" in
        *.asc|*.md5|*.sha1|*.sha256|*.sha512|*/maven-metadata.xml*) continue ;;
    esac
    if [ ! -f "$file.asc" ]; then
        echo "MISSING SIGNATURE ${file#"$repo"/}"
        missing=$((missing + 1))
    elif gpg --homedir "$home" --batch --quiet --verify "$file.asc" "$file" 2>/dev/null; then
        verified=$((verified + 1))
    else
        echo "BAD SIGNATURE ${file#"$repo"/}"
        failed=$((failed + 1))
    fi
done < <(find "$repo" -type f -print0)

echo "signatures: verified=$verified bad=$failed missing=$missing"
[ "$verified" -gt 0 ] && [ "$failed" -eq 0 ] && [ "$missing" -eq 0 ]
