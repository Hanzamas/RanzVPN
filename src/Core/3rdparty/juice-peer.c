/**
 * Copyright (c) 2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// juice-peer.c
// The peer mode of libjuice 1.7.4 for Ranz VPN (CORE-S5-6, #412; juice-peer.h): the connection of an agent whose
// socket is the socket of the peer layer of a node. It stands in the place of conn_thread.c, the thread mode of
// libjuice, changed from it for Ranz VPN, and has its interface (conn_thread.h), so conn.c runs an agent made with
// JUICE_CONCURRENCY_MODE_THREAD on it; src/Core/3rdparty/CMakeLists.txt builds this file in place of that one. It keeps
// the notices of conn_thread.c and its licence, the Mozilla Public License 2.0 (controller/cmd/ranz/NOTICE).
//
// As in the thread mode, each agent has a thread of its own, which runs the timers of the agent (its checks, their
// retransmissions, consent freshness) under the mutex of the agent and sleeps until the next one is due or the agent
// is interrupted. It owns no socket: the agent sends through the send procedure of its I/O (juice_peer_io_t), and the
// peer layer hands it the STUN messages that come to its socket (juice_peer_input), which the agent takes under the
// same mutex, as the thread mode takes what its socket receives. The host candidates of the agent are the host
// addresses of the I/O. Data never goes through the agent: the peer layer sends its records on the pair that the agent
// selected (juice_peer_selected) and takes them itself.

#include "conn_thread.h"
#include "agent.h"
#include "log.h"
#include "socket.h"
#include "stun.h"
#include "thread.h"

#include "juice-peer.h"

#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096

typedef struct conn_impl {
	const juice_peer_io_t *io;  // The I/O of the agent: the start of the struct at its user_ptr
	thread_t thread;            // The thread of the agent's timers
	HANDLE wake;                // Set when the thread must look at the timers again
	mutex_t mutex;              // The agent: everything that libjuice does with it (recursive, for the callbacks)
	timestamp_t next_timestamp; // When the timers of the agent are due next
	bool stopped;               // The agent ends: the thread returns and no message is taken any more
} conn_impl_t;

static thread_return_t THREAD_CALL conn_peer_entry(void *arg) {
	juice_agent_t *agent = (juice_agent_t *)arg;
	conn_impl_t *conn_impl = agent->conn_impl;

	thread_set_name_self("juice peer");

	while (true) {
		mutex_lock(&conn_impl->mutex);
		if (conn_impl->stopped) {
			mutex_unlock(&conn_impl->mutex);
			break;
		}

		if (conn_impl->next_timestamp <= current_timestamp() && agent_conn_update(agent, &conn_impl->next_timestamp) != 0)
			JLOG_WARN("Agent update failed");

		timediff_t timediff = conn_impl->next_timestamp - current_timestamp();
		mutex_unlock(&conn_impl->mutex);

		if (timediff < 0)
			timediff = 0;

		JLOG_VERBOSE("Waiting for %d ms", (int)timediff);
		WaitForSingleObject(conn_impl->wake, (DWORD)timediff);
	}

	JLOG_DEBUG("Leaving connection thread");
	return (thread_return_t)0;
}

int conn_thread_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
	(void)registry;
	(void)config;

	const juice_peer_io_t *io = (const juice_peer_io_t *)agent->config.user_ptr;
	if (!io || !io->send) {
		JLOG_ERROR("An agent of the peer mode needs the I/O of the peer layer at its user pointer");
		return -1;
	}

	conn_impl_t *conn_impl = calloc(1, sizeof(conn_impl_t));
	if (!conn_impl) {
		JLOG_FATAL("Memory allocation failed for connection impl");
		return -1;
	}

	conn_impl->io = io;
	conn_impl->next_timestamp = current_timestamp();
	conn_impl->wake = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (conn_impl->wake == NULL || mutex_init(&conn_impl->mutex, MUTEX_RECURSIVE) != 0) {
		JLOG_FATAL("The event or the mutex of the connection could not be made");
		if (conn_impl->wake != NULL)
			CloseHandle(conn_impl->wake);
		free(conn_impl);
		return -1;
	}

	agent->conn_impl = conn_impl;

	JLOG_DEBUG("Starting connection thread");
	int ret = thread_init(&conn_impl->thread, conn_peer_entry, agent);
	if (ret) {
		JLOG_FATAL("Thread creation failed, error=%d", ret);
		mutex_destroy(&conn_impl->mutex);
		CloseHandle(conn_impl->wake);
		free(conn_impl);
		agent->conn_impl = NULL;
		return -1;
	}

	return 0;
}

void conn_thread_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->mutex);
	conn_impl->stopped = true;
	mutex_unlock(&conn_impl->mutex);

	SetEvent(conn_impl->wake);

	JLOG_VERBOSE("Waiting for connection thread");
	thread_join(conn_impl->thread, NULL);

	CloseHandle(conn_impl->wake);
	mutex_destroy(&conn_impl->mutex);
	free(agent->conn_impl);
	agent->conn_impl = NULL;
}

void conn_thread_lock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_lock(&conn_impl->mutex);
}

void conn_thread_unlock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_unlock(&conn_impl->mutex);
}

int conn_thread_interrupt(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->mutex);
	conn_impl->next_timestamp = current_timestamp();
	mutex_unlock(&conn_impl->mutex);

	JLOG_VERBOSE("Interrupting connection thread");
	SetEvent(conn_impl->wake);
	return 0;
}

// The send procedure of the I/O takes no lock of the agent: the peer layer may hold its own lock while it sends
int conn_thread_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size, int ds) {
	conn_impl_t *conn_impl = agent->conn_impl;
	(void)ds;

	JLOG_VERBOSE("Sending datagram, size=%d", (int)size);

	int ret = conn_impl->io->send(agent->config.user_ptr, (const struct sockaddr *)&dst->addr, (int)dst->len, data, size);
	if (ret < 0)
		JLOG_INFO("Send failed");

	return ret;
}

int conn_thread_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;
	struct sockaddr_storage addrs[JUICE_PEER_MAX_ADDRS];

	int num = (conn_impl->io->get_addrs != NULL ? conn_impl->io->get_addrs(agent->config.user_ptr, addrs, JUICE_PEER_MAX_ADDRS) : 0);
	if (num < 0)
		return -1;
	if (num > JUICE_PEER_MAX_ADDRS)
		num = JUICE_PEER_MAX_ADDRS;

	int count = 0;
	for (int i = 0; i < num && (size_t)count < size; i++) {
		socklen_t len = addr_get_len((const struct sockaddr *)&addrs[i]);
		if (len == 0)
			continue;

		memset(&records[count], 0, sizeof(addr_record_t));
		memcpy(&records[count].addr, &addrs[i], len);
		records[count].len = len;
		records[count].socktype = SOCK_DGRAM;
		count++;
	}

	return count;
}

bool juice_peer_is_stun(const char *data, size_t size) {
	return data != NULL && is_stun_datagram(data, size);
}

// Whether the agent takes the STUN message msg: a binding request that names its username fragment first, or an answer
// to one of its own requests. Under the mutex of the agent.
static bool conn_peer_takes(juice_agent_t *agent, const stun_message_t *msg) {
	if (msg->msg_class == STUN_CLASS_REQUEST && msg->msg_method == STUN_METHOD_BINDING && msg->has_integrity) {
		const char *separator = strchr(msg->credentials.username, ':');
		size_t len = strlen(agent->local.ice_ufrag);

		return separator != NULL && len != 0 && (size_t)(separator - msg->credentials.username) == len &&
		       strncmp(msg->credentials.username, agent->local.ice_ufrag, len) == 0;
	}

	return STUN_IS_RESPONSE(msg->msg_class) && agent_find_entry_from_transaction_id(agent, msg->transaction_id) != NULL;
}

bool juice_peer_input(juice_agent_t *agent, const char *data, size_t size, const struct sockaddr *src, int src_len) {
	char buffer[BUFFER_SIZE];
	stun_message_t msg;
	addr_record_t record;

	if (agent == NULL || data == NULL || src == NULL || size > sizeof(buffer) || src_len <= 0 || (size_t)src_len > sizeof(record.addr) ||
	    is_stun_datagram(data, size) == false)
		return false;

	conn_impl_t *conn_impl = agent->conn_impl;
	if (conn_impl == NULL)
		return false;

	// stun_read reads a copy: the agent reads the message again from a copy of its own
	memcpy(buffer, data, size);
	if (stun_read(buffer, size, &msg) < 0)
		return false;

	memset(&record, 0, sizeof(record));
	memcpy(&record.addr, src, (size_t)src_len);
	record.len = (socklen_t)src_len;
	record.socktype = SOCK_DGRAM;
	addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr, &record.len);

	mutex_lock(&conn_impl->mutex);

	// An agent that failed answers nothing, so that the consent of its peer fails too and both ends leave the pair
	bool taken = (conn_impl->stopped == false && agent->state != JUICE_STATE_FAILED && conn_peer_takes(agent, &msg));
	if (taken) {
		memcpy(buffer, data, size);
		agent_conn_recv(agent, buffer, size, &record);
		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0)
			JLOG_WARN("Agent update failed");
	}

	mutex_unlock(&conn_impl->mutex);

	// The thread waits for the next timer that the message set
	if (taken)
		SetEvent(conn_impl->wake);

	return taken;
}

int juice_peer_selected(juice_agent_t *agent, struct sockaddr_storage *addr) {
	ice_candidate_t remote;

	if (agent == NULL || addr == NULL || agent_get_selected_candidate_pair(agent, NULL, &remote) != 0)
		return -1;

	socklen_t len = remote.resolved.len;
	if (len == 0 || len > sizeof(struct sockaddr_storage))
		return -1;

	memset(addr, 0, sizeof(struct sockaddr_storage));
	memcpy(addr, &remote.resolved.addr, len);
	return (int)len;
}
