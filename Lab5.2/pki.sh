#!/usr/bin/env bash
# =====================================================================
# Lab 5.2 - Internal PKI (OpenSSL) + Digital Signature
# Creates a root CA (RSA 4096, self-signed cert valid 3650 days),
# issues user certificates (RSA >=2048, valid 365 days), lets each
# user sign and verify files, and supports revocation via CRL.
# Usage: ./pki.sh <command> [args]
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")/pki"

CA_KEY=ca/ca.key.pem
CA_CERT=ca/ca.cert.pem
CONF=openssl.cnf

log() { echo -e "\n\033[1;36m==> $*\033[0m"; }

# --------------------------------------------------------------------
init_ca() {
    log "Generating CA private key (RSA 4096)"
    openssl genrsa -out "$CA_KEY" 4096

    log "Creating self-signed CA certificate (valid 3650 days = 10 years)"
    openssl req -config "$CONF" -key "$CA_KEY" -new -x509 \
        -days 3650 -sha256 -extensions v3_ca \
        -subj "/C=MD/ST=Chisinau/L=Chisinau/O=Internal PKI Lab/OU=Certification Authority/CN=Lab Root CA" \
        -out "$CA_CERT"

    log "CA initialized:"
    openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates -text | grep -E "Subject:|Issuer:|notBefore|notAfter|Public-Key"
}

# --------------------------------------------------------------------
issue_user() {
    local USER="$1" BITS="${2:-2048}"
    [[ $BITS -ge 2048 ]] || { echo "Key size must be >= 2048 bits"; exit 1; }
    local UDIR="users/$USER"
    mkdir -p "$UDIR"

    log "[$USER] Generating user private key (RSA $BITS)"
    openssl genrsa -out "$UDIR/$USER.key.pem" "$BITS"

    log "[$USER] Creating CSR"
    openssl req -config "$CONF" -new -sha256 \
        -key "$UDIR/$USER.key.pem" \
        -subj "/C=MD/ST=Chisinau/L=Chisinau/O=Internal PKI Lab/OU=Users/CN=$USER" \
        -out "$UDIR/$USER.csr.pem"

    log "[$USER] CA signs the certificate (valid 365 days)"
    [[ -f ca/crl/ca.crl.pem ]] || openssl ca -config "$CONF" -batch -gencrl -out ca/crl/ca.crl.pem
    openssl ca -config "$CONF" -batch -extensions v3_user -days 365 \
        -notext -md sha256 -in "$UDIR/$USER.csr.pem" \
        -out "$UDIR/$USER.cert.pem"

    # verification chain file for signature validation
    cat "$UDIR/$USER.cert.pem" "$CA_CERT" > "$UDIR/$USER.chain.pem"

    log "[$USER] Issued certificate:"
    openssl x509 -in "$UDIR/$USER.cert.pem" -noout -subject -issuer -dates -serial -text | grep -E "Subject:|Issuer:|notBefore|notAfter|Serial|Public-Key"
}

# --------------------------------------------------------------------
sign_file() {
    local USER="$1" FILE="$2"
    local UDIR="users/$USER"
    [[ -f "$UDIR/$USER.key.pem" && -f "$UDIR/$USER.cert.pem" ]] || { echo "User '$USER' not enrolled"; exit 1; }
    [[ -f "$FILE" ]] || { echo "File '$FILE' not found"; exit 1; }

    log "[$USER] Signing '$FILE' (SHA-256 + RSA with the user's private key)"
    openssl dgst -sha256 -sign "$UDIR/$USER.key.pem" -out "$FILE.sig.bin" "$FILE"
    base64 "$FILE.sig.bin" > "$FILE.sig"
    echo "Signature written to $FILE.sig"
}

verify_file() {
    local USER="$1" FILE="$2"
    local UDIR="users/$USER"

    log "[$USER] Verifying signature of '$FILE' against the CA chain"
    if openssl dgst -sha256 -verify <(openssl x509 -in "$UDIR/$USER.cert.pem" -pubkey -noout) \
        -signature "$FILE.sig.bin" "$FILE" \
        && openssl verify -CAfile "$CA_CERT" -crl_check -CRLfile ca/crl/ca.crl.pem "$UDIR/$USER.cert.pem"; then
        echo "RESULT: signature VALID and certificate trusted/not revoked"
    else
        echo "RESULT: verification FAILED (bad signature or revoked/untrusted certificate)"
        return 1
    fi
}

# --------------------------------------------------------------------
revoke_user() {
    local USER="$1"
    log "[$USER] Revoking certificate and updating CRL"
    openssl ca -config "$CONF" -batch -revoke "users/$USER/$USER.cert.pem" -crl_reason keyCompromise
    openssl ca -config "$CONF" -batch -gencrl -out ca/crl/ca.crl.pem
    echo "Revocation database (index.txt):"
    cat ca/index.txt
}

show_crl() {
    log "Current CRL"
    openssl crl -in ca/crl/ca.crl.pem -noout -text | sed -n '1,25p'
}

status() {
    log "PKI status"
    echo "--- CA ---"; openssl x509 -in "$CA_CERT" -noout -subject -dates 2>/dev/null || echo "(CA not initialized)"
    echo "--- Registered entities ---"; cat ca/index.txt 2>/dev/null || true
    echo "--- Users ---"; ls users 2>/dev/null || true
}

# --------------------------------------------------------------------
case "${1:-help}" in
    init)            init_ca ;;
    issue)           issue_user "${2:?usage: pki.sh issue <user> [bits]}" "${3:-2048}" ;;
    sign)            sign_file "${2:?usage: pki.sh sign <user> <file>}" "${3:?}" ;;
    verify)          verify_file "${2:?usage: pki.sh verify <user> <file>}" "${3:?}" ;;
    revoke)          revoke_user "${2:?usage: pki.sh revoke <user>}" ;;
    crl)             show_crl ;;
    status)          status ;;
    *) cat <<EOF
Lab 5.2 - internal PKI with OpenSSL + DSA-style digital signatures
Commands:
  ./pki.sh init                 create CA (RSA-4096 key, self-signed cert, 10 years)
  ./pki.sh issue <user> [bits]  enroll a user (RSA key >=2048, cert valid 365 days)
  ./pki.sh sign  <user> <file>  sign a file with the user's private key
  ./pki.sh verify <user> <file> verify signature + certificate chain + CRL
  ./pki.sh revoke <user>        revoke the user's certificate and refresh CRL
  ./pki.sh crl                  show the current CRL
  ./pki.sh status               show PKI state
EOF
       ;;
esac
