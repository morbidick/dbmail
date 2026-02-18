/*
 Copyright (c) 2004-2013 NFG Net Facilities Group BV support@nfg.nl
 Copyright (c) 2014-2019 Paul J Stevens, The Netherlands, support@nfg.nl
 Copyright (c) 2020-2026 Alan Hicks, Persistent Objects Ltd support@p-o.co.uk

 This program is free software; you can redistribute it and/or 
 modify it under the terms of the GNU General Public License 
 as published by the Free Software Foundation; either 
 version 2 of the License, or (at your option) any later 
 version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* 
 *
 * clientbase — bufferevent_openssl based I/O layer
 */

#include <openssl/err.h>
#include "dbmail.h"
#include "dm_mempool.h"

#define THIS_MODULE "clientbase"

extern DBParam_T db_params;
#define DBPFX db_params.pfx

extern ServerConfig_T *server_conf;
extern SSL_CTX *tls_context;
extern struct event_base *evbase;

/* ------------------------------------------------------------------ */
/*  helpers                                                            */
/* ------------------------------------------------------------------ */

static void dm_tls_error(void)
{
	unsigned long e;
	while ((e = ERR_get_error()))
		TRACE(TRACE_INFO, "%s", ERR_error_string(e, NULL));
}

/* ------------------------------------------------------------------ */
/*  bufferevent event callback (EOF / error / timeout / TLS done)      */
/* ------------------------------------------------------------------ */

static void client_bev_event_cb(struct bufferevent *bev, short what, void *arg)
{
	ClientBase_T *client = (ClientBase_T *)arg;

	if (what & BEV_EVENT_CONNECTED) {
		/* TLS handshake completed (implicit TLS or STARTTLS) */
		TRACE(TRACE_DEBUG, "[%p] TLS handshake completed", client);
		client->sock->ssl_state = TRUE;
		return;
	}

	if (what & BEV_EVENT_TIMEOUT) {
		TRACE(TRACE_DEBUG, "[%p] timeout", client);
		if (client->cb_time)
			client->cb_time(arg);
		return;
	}

	if (what & BEV_EVENT_EOF) {
		TRACE(TRACE_DEBUG, "[%p] EOF", client);
		PLOCK(client->lock);
		client->client_state |= CLIENT_EOF;
		PUNLOCK(client->lock);
	}

	if (what & BEV_EVENT_ERROR) {
		unsigned long sslerr;
		TRACE(TRACE_DEBUG, "[%p] error: %s", client,
		      evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		while ((sslerr = bufferevent_get_openssl_error(bev)))
			TRACE(TRACE_INFO, "SSL error: %s", ERR_error_string(sslerr, NULL));
		PLOCK(client->lock);
		client->client_state |= CLIENT_ERR;
		PUNLOCK(client->lock);
	}
}

/* ------------------------------------------------------------------ */
/*  client_init                                                        */
/* ------------------------------------------------------------------ */

ClientBase_T * client_init(client_sock *c)
{
	int serr;
	ClientBase_T *client;
	Mempool_T pool = c->pool;

	client           = mempool_pop(pool, sizeof(ClientBase_T));
	client->pool     = pool;
	client->sock     = c;

	pthread_mutex_init(&client->lock, NULL);

	/* set byte counters to 0 */
	client->bytes_rx = 0;
	client->bytes_tx = 0;

	/* make streams */
	if (c->caddr_len == 0) {
		client->rx		= STDIN_FILENO;
		client->tx		= STDOUT_FILENO;
	} else {
		/* server-side */
		if ((serr = getnameinfo(&c->saddr, c->saddr_len, client->dst_ip,
			NI_MAXHOST, client->dst_port,
			NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV))) {
			TRACE(TRACE_INFO, "getnameinfo::error [%s]", gai_strerror(serr));
		}

		/* client-side */
		if ((serr = getnameinfo(&c->caddr, c->caddr_len, client->src_ip,
			NI_MAXHOST-1, client->src_port,
			NI_MAXSERV-1, NI_NUMERICHOST | NI_NUMERICSERV))) {
			TRACE(TRACE_INFO, "getnameinfo:error [%s]", gai_strerror(serr));
		}
		if (server_conf->resolveIP) {
			if ((serr = getnameinfo(&c->caddr, c->caddr_len, client->clientname,
				NI_MAXHOST-1, NULL, 0, NI_NAMEREQD))) {
				TRACE(TRACE_INFO, "getnameinfo:error [%s]", gai_strerror(serr));
			}
			TRACE(TRACE_NOTICE, "incoming connection on [%s:%s] from [%s:%s (%s)]",
			      client->dst_ip, client->dst_port, client->src_ip, client->src_port,
			      client->clientname[0] ? client->clientname : "Lookup failed");
		} else {
			TRACE(TRACE_NOTICE, "incoming connection on [%s:%s] from [%s:%s]",
			      client->dst_ip, client->dst_port, client->src_ip, client->src_port);
		}

		/* store fd for metadata access */
		client->rx = client->tx = c->sock;
	}

	/* Create the bufferevent */
	if (c->caddr_len == 0) {
		/* stdin/stdout mode (inetd) — plain bufferevent */
		client->bev = bufferevent_socket_new(evbase, STDIN_FILENO, 0);
	} else if (c->ssl_state == -1) {
		/* implicit TLS — create SSL bev, handshake is async */
		SSL *ssl = tls_setup_new();
		if (!ssl) {
			TRACE(TRACE_ERR, "[%p] tls_setup_new failed for implicit TLS", client);
			/* fall back to plain so caller can handle error */
			client->bev = bufferevent_socket_new(evbase, c->sock,
				BEV_OPT_CLOSE_ON_FREE);
		} else {
			client->bev = bufferevent_openssl_socket_new(evbase, c->sock,
				ssl, BUFFEREVENT_SSL_ACCEPTING,
				BEV_OPT_CLOSE_ON_FREE);
		}
	} else {
		/* plain connection */
		client->bev = bufferevent_socket_new(evbase, c->sock,
			BEV_OPT_CLOSE_ON_FREE);
	}

	if (!client->bev) {
		TRACE(TRACE_ERR, "[%p] failed to create bufferevent", client);
		pthread_mutex_destroy(&client->lock);
		mempool_push(pool, client, sizeof(ClientBase_T));
		return NULL;
	}

	/* Set the generic event callback for error/eof/timeout/connected */
	bufferevent_setcb(client->bev, NULL, NULL, client_bev_event_cb, client);

	return client;
}

/* ------------------------------------------------------------------ */
/*  cork / uncork                                                      */
/* ------------------------------------------------------------------ */

void ci_cork(ClientBase_T *s)
{
	TRACE(TRACE_DEBUG,"[%p] [%d] [%d]", s, s->rx, s->tx);
	if (s->bev) bufferevent_disable(s->bev, EV_READ|EV_WRITE);
}

void ci_uncork(ClientBase_T *s)
{
	int state;
	TRACE(TRACE_DEBUG,"[%p] [%d] [%d], [%ld]", s, s->rx, s->tx, s->timeout.tv_sec);

	PLOCK(s->lock);
	state = s->client_state;
	PUNLOCK(s->lock);

	if (state & CLIENT_ERR)
		return;

	if (s->bev) {
		bufferevent_set_timeouts(s->bev, &s->timeout, NULL);
		if (! (state & CLIENT_EOF))
			bufferevent_enable(s->bev, EV_READ|EV_WRITE);
		else
			bufferevent_enable(s->bev, EV_WRITE);
	}
}

/* ------------------------------------------------------------------ */
/*  ci_starttls — STARTTLS upgrade via filter                          */
/* ------------------------------------------------------------------ */

int ci_starttls(ClientBase_T *client)
{
	SSL *ssl;
	struct bufferevent *new_bev;
	bufferevent_data_cb readcb, writecb;
	bufferevent_event_cb eventcb;
	void *cbarg;

	TRACE(TRACE_DEBUG,"[%p] ssl_state [%d]", client, client->sock->ssl_state);
	if (client->sock->ssl_state > 0) {
		TRACE(TRACE_WARNING, "ssl already initialized");
		return DM_EGENERAL;
	}

	ssl = tls_setup_new();
	if (!ssl) {
		TRACE(TRACE_ERR, "[%p] tls_setup_new failed", client);
		return DM_EGENERAL;
	}

	/* Preserve protocol-level callbacks before wrapping */
	bufferevent_getcb(client->bev, &readcb, &writecb, &eventcb, &cbarg);

	new_bev = bufferevent_openssl_filter_new(evbase, client->bev,
		ssl, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE);

	if (!new_bev) {
		TRACE(TRACE_ERR, "[%p] bufferevent_openssl_filter_new failed", client);
		SSL_free(ssl);
		return DM_EGENERAL;
	}

	/* The old bev is now owned by the filter — reassign */
	client->bev = new_bev;
	/* Re-apply the protocol-level callbacks on the new SSL bev */
	bufferevent_setcb(client->bev, readcb, writecb, eventcb, cbarg);
	/* Handshake proceeds asynchronously; BEV_EVENT_CONNECTED signals completion */

	return DM_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  write                                                              */
/* ------------------------------------------------------------------ */

void ci_write_cb(ClientBase_T *client)
{
	/* With bufferevent, writes are fully managed. This callback is
	 * provided for callers that still use the old ci_write_cb pattern.
	 * Flush any pending formatted data. */
	if (client->cb_write)
		client->cb_write(client);
}

int ci_write(ClientBase_T *client, char * msg, ...)
{
	va_list ap, cp;
	int state;
	char *buf = NULL;

	if (!client || !client->bev)
		return -1; // stale

	PLOCK(client->lock);
	state = client->client_state;
	PUNLOCK(client->lock);

	if (state & CLIENT_ERR)
		return -1; // disconnected

	if (msg) {
		va_start(ap, msg);
		va_copy(cp, ap);
		buf = g_strdup_vprintf(msg, cp);
		va_end(cp);
		va_end(ap);

		if (buf) {
			size_t len = strlen(buf);
			TRACE(TRACE_DEBUG, "[%p] S > [%zu:%s]", client, len, buf);
			if (bufferevent_write(client->bev, buf, len) < 0) {
				g_free(buf);
				PLOCK(client->lock);
				client->client_state |= CLIENT_ERR;
				PUNLOCK(client->lock);
				return -1;
			}
			client->bytes_tx += len;
			g_free(buf);
		}
	}

	return 1;
}

size_t ci_wbuf_len(ClientBase_T *client)
{
	int state;

	PLOCK(client->lock);
	state = client->client_state;
	PUNLOCK(client->lock);

	if (state & CLIENT_ERR)
		return 0;

	if (client->bev) {
		struct evbuffer *output = bufferevent_get_output(client->bev);
		return output ? evbuffer_get_length(output) : 0;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  read                                                               */
/* ------------------------------------------------------------------ */

void ci_read_cb(ClientBase_T *client)
{
	/* With bufferevent, data is already in the input evbuffer
	 * when the read callback fires. This function is now a
	 * compatibility shim — the actual data is accessed via
	 * ci_read / ci_readln which pull from the evbuffer. 
	 *
	 * Check for EOF/error state from the bev. */
	struct evbuffer *input;
	size_t have;

	if (!client || !client->bev) return;

	input = bufferevent_get_input(client->bev);
	have = evbuffer_get_length(input);

	TRACE(TRACE_DEBUG, "[%p] [%zu bytes available]", client, have);

	if (have > 0) {
		client->bytes_rx += have; /* approximate — count on access */
		PLOCK(client->lock);
		client->client_state = CLIENT_OK;
		PUNLOCK(client->lock);
	}
}

int ci_read(ClientBase_T *client, char *buffer, size_t n)
{
	struct evbuffer *input;
	size_t have;

	assert(buffer);
	client->len = 0;

	if (!client->bev) return 0;

	input = bufferevent_get_input(client->bev);
	have = evbuffer_get_length(input);

	if (have >= n) {
		evbuffer_remove(input, buffer, n);
		client->len = n;
	}

	return client->len;
}

int ci_readln(ClientBase_T *client, char * buffer)
{
	struct evbuffer *input;
	struct evbuffer_ptr ptr;
	size_t line_len;

	assert(buffer);
	client->len = 0;

	if (!client->bev) return 0;

	input = bufferevent_get_input(client->bev);

	/* Search for \n in the input buffer */
	ptr = evbuffer_search(input, "\n", 1, NULL);
	if (ptr.pos < 0)
		return 0; /* no complete line yet */

	line_len = ptr.pos + 1; /* include the \n */

	if (line_len >= MAX_LINESIZE) {
		TRACE(TRACE_WARNING, "insane line-length [%zu]", line_len);
		PLOCK(client->lock);
		client->client_state |= CLIENT_ERR;
		PUNLOCK(client->lock);
		return 0;
	}

	evbuffer_remove(input, buffer, line_len);
	client->len = line_len;

	TRACE(TRACE_INFO, "[%p] C < [%" PRIu64 ":%s]", client, client->len, buffer);

	return client->len;
}


/* ------------------------------------------------------------------ */
/*  auth logging (unchanged)                                           */
/* ------------------------------------------------------------------ */

void ci_authlog_init(ClientBase_T *client, const char *service, const char *username, const char *status)
{
	if ((! server_conf->authlog) || server_conf->no_daemonize == 1) return;
	Connection_T c; ResultSet_T r; PreparedStatement_T s;
	const char *now = db_get_sql(SQL_CURRENT_TIMESTAMP);
	char *frag = db_returning("id");
	c = db_con_get();
	TRY
		const char *user = client->auth?Cram_getUsername(client->auth):username;

		s = db_stmt_prepare(c, "INSERT INTO %sauthlog (userid, service, login_time, logout_time, src_ip, src_port, dst_ip, dst_port, status)"
				" VALUES (?, ?, %s, %s, ?, ?, ?, ?, ?) %s", DBPFX, now, now, frag);

		g_free(frag);
		db_stmt_set_str(s, 1, user);
		db_stmt_set_str(s, 2, service);
		db_stmt_set_str(s, 3, (char *)client->src_ip);
		db_stmt_set_int(s, 4, atoi(client->src_port));
		db_stmt_set_str(s, 5, (char *)client->dst_ip);
		db_stmt_set_int(s, 6, atoi(client->dst_port));
		db_stmt_set_str(s, 7, status);

		r = db_stmt_query(s);
		
		if(strcmp(AUTHLOG_ERR,status)!=0) client->authlog_id = db_insert_result(c, r);
	CATCH(SQLException)
		LOG_SQLERROR;
	FINALLY
		db_con_close(c);
	END_TRY;

}

static void ci_authlog_close(ClientBase_T *client)
{
	Connection_T c; PreparedStatement_T s;
	if (! client->authlog_id) return;
	if ((! server_conf->authlog) || server_conf->no_daemonize) return;
	const char *now = db_get_sql(SQL_CURRENT_TIMESTAMP);
	c = db_con_get();
	TRY
		s = db_stmt_prepare(c, "UPDATE %sauthlog SET logout_time=%s, status=?, bytes_rx=?, bytes_tx=? "
		"WHERE id=?", DBPFX, now);
		db_stmt_set_str(s, 1, AUTHLOG_FIN);
		db_stmt_set_u64(s, 2, client->bytes_rx);
		db_stmt_set_u64(s, 3, client->bytes_tx);
		db_stmt_set_u64(s, 4, client->authlog_id);

		db_stmt_exec(s);
	CATCH(SQLException)
		LOG_SQLERROR;
	FINALLY
		db_con_close(c);
	END_TRY;
}

/* ------------------------------------------------------------------ */
/*  ci_close                                                           */
/* ------------------------------------------------------------------ */

void ci_close(ClientBase_T *client)
{
	assert(client);

	TRACE(TRACE_DEBUG, "closing clientbase [%p] [%d] [%d]", client,
			client->tx, client->rx);

	ci_cork(client);

	if (client->bev) {
		/* BEV_OPT_CLOSE_ON_FREE handles fd close and SSL teardown */
		bufferevent_free(client->bev);
		client->bev = NULL;
	}

	client->tx = -1;
	client->rx = -1;

	ci_authlog_close(client);

	if (client->auth) {
		Cram_T c = client->auth;
		Cram_free(&c);
		client->auth = NULL;
	}

	pthread_mutex_destroy(&client->lock);

	Mempool_T pool = client->pool;
	mempool_push(pool, client->sock, sizeof(client_sock));
	client->sock = NULL;

	mempool_push(pool, client, sizeof(ClientBase_T));
	client = NULL;
}


