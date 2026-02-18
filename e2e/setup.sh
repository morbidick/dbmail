SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$SCRIPT_DIR/tmp"
CERTS_DIR="$TMP_DIR/certs"
DBMAIL_CONF_SRC="$SCRIPT_DIR/../dbmail.conf"
DBMAIL_CONF_DST="$TMP_DIR/dbmail.conf"

echo "e2e setup"
mkdir -p "$TMP_DIR"


echo "create dbmail.conf"
cp "$DBMAIL_CONF_SRC" "$DBMAIL_CONF_DST"
sed -i 's!file_logging_levels.*!file_logging_levels = info!' "$DBMAIL_CONF_DST"
sed -i 's!dburi.*!dburi = postgresql://dbmail:dbpassword@localhost:5432/dbmail!' "$DBMAIL_CONF_DST"
sed -i 's!tls_cafile.*!tls_cafile = /certs/ca.crt!' "$DBMAIL_CONF_DST"
sed -i 's!tls_cert.*!tls_cert = /certs/server.crt!' "$DBMAIL_CONF_DST"
sed -i 's!tls_key.*!tls_key = /certs/server.key!' "$DBMAIL_CONF_DST"
sed -i 's!#tls_port.*= 993.*!tls_port = 993!' "$DBMAIL_CONF_DST"
sed -i 's!# login_disabled.*!login_disabled = no!' "$DBMAIL_CONF_DST"

echo "build container"
podman build $SCRIPT_DIR/.. -f $SCRIPT_DIR/../docker/Dockerfile-amd64-ubuntu-devel -t dbmail:local


if [ -f "$CERTS_DIR/server.crt" ]; then
	echo "server certificate already exists, skipping generation"
	exit 0
fi

echo "create server certificate"
CANAME=ca
MYCERT=server
OPENSSL_PASS="${OPENSSL_PASS:-test}"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR" || exit 1
# generate aes encrypted private key
openssl genrsa -aes256 -passout pass:"$OPENSSL_PASS" -out $CANAME.key 4096
# create certificate, 1826 days = 5 years
openssl req -x509 -new -nodes -key $CANAME.key -passin pass:"$OPENSSL_PASS" -sha256 -days 1826 -out $CANAME.crt -subj '/CN=My Root CA/C=AT/ST=Vienna/L=Vienna/O=MyOrganisation'
# create certificate for service

openssl req -new -nodes -out $MYCERT.csr -newkey rsa:4096 -keyout $MYCERT.key -subj '/CN=My Firewall/C=AT/ST=Vienna/L=Vienna/O=MyOrganisation'
# create a v3 ext file for SAN properties
cat > $MYCERT.v3.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = myserver.local
DNS.2 = myserver1.local
IP.1 = 192.168.1.1
IP.2 = 192.168.2.1
EOF
openssl x509 -req -in $MYCERT.csr -CA $CANAME.crt -CAkey $CANAME.key -passin pass:"$OPENSSL_PASS" -CAcreateserial -out $MYCERT.crt -days 730 -sha256 -extfile $MYCERT.v3.ext
