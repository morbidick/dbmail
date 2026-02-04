set -x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
podman pod create --replace --name dbmail-test -p 1143:143 -p 1993:993
podman run --pod dbmail-test -d --replace --name dbmail-test-postgres \
  -e POSTGRES_DB=dbmail \
  -e POSTGRES_USER=dbmail \
  -e POSTGRES_PASSWORD=dbpassword \
  docker.io/postgres:16-alpine
echo "Waiting for PostgreSQL to be ready..."
until podman exec dbmail-test-postgres pg_isready -U postgres &>/dev/null; do
  sleep 1
done
echo "PostgreSQL is ready."

podman run --pod dbmail-test -d --rm --replace --name dbmail-test-imap  -v $SCRIPT_DIR/tmp/certs:/certs:Z -v $SCRIPT_DIR/tmp/dbmail.conf:/usr/local/etc/dbmail.conf:Z dbmail:local bash -c "dbmail-imapd -D"
podman exec dbmail-test-imap bash -c "dbmail-util -ay"
podman exec dbmail-test-imap bash -c "dbmail-users -a test -w changeme123"
podman exec -it dbmail-test-imap bash -c "tail -f /var/log/dbmail/dbmail.log"
