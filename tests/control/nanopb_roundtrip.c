// nanopb_roundtrip.c
// The C side of the control protocol schema (SDN-2, #178)
//
// Every control message that the controller conformance tests sent or received
// (controller/internal/controller and the cluster tests of controller/cluster_test.go, written
// with RANZ_CONTROL_WIRE) is decoded with the code that nanopb generates from
// proto/ranz/control/v1/control.proto and control.options, then encoded again. The bytes must come out the same, so the C node and the controller agree on every field
// of the messages the controller sends and of the ones a node sends.
//
// Usage: nanopb_roundtrip FILE...   (exit status 0 when every file round trips)

#include <stdio.h>
#include <string.h>

#include <pb_decode.h>
#include <pb_encode.h>

#include "ranz/control/v1/control.pb.h"

// The largest frame of the tests is far below this
#define MAX_FRAME (64 * 1024)

static pb_byte_t in[MAX_FRAME];
static pb_byte_t out[MAX_FRAME];
static ranz_control_v1_ControlMessage msg;

static const char *body_name(pb_size_t which) {
	switch (which) {
	case ranz_control_v1_ControlMessage_hello_tag:
		return "Hello";
	case ranz_control_v1_ControlMessage_update_tag:
		return "Update";
	case ranz_control_v1_ControlMessage_ack_tag:
		return "Ack";
	case ranz_control_v1_ControlMessage_refuse_tag:
		return "Refuse";
	case ranz_control_v1_ControlMessage_signal_tag:
		return "Signal";
	case ranz_control_v1_ControlMessage_controllers_tag:
		return "Controllers";
	case ranz_control_v1_ControlMessage_telemetry_tag:
		return "Telemetry";
	case ranz_control_v1_ControlMessage_leases_tag:
		return "Leases";
	case ranz_control_v1_ControlMessage_operation_tag:
		return "Operation";
	case ranz_control_v1_ControlMessage_operation_result_tag:
		return "OperationResult";
	case ranz_control_v1_ControlMessage_pins_tag:
		return "Pins";
	default:
		return "nothing";
	}
}

// Decode, encode and compare one file; print what it held
static int roundtrip(const char *path) {
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		fprintf(stderr, "%s: cannot open\n", path);
		return 0;
	}
	size_t n = fread(in, 1, sizeof(in), f);
	int too_big = !feof(f);
	fclose(f);
	if (too_big) {
		fprintf(stderr, "%s: larger than %d bytes\n", path, MAX_FRAME);
		return 0;
	}

	memset(&msg, 0, sizeof(msg));
	pb_istream_t is = pb_istream_from_buffer(in, n);
	if (!pb_decode(&is, ranz_control_v1_ControlMessage_fields, &msg)) {
		fprintf(stderr, "%s: decode: %s\n", path, PB_GET_ERROR(&is));
		return 0;
	}
	pb_ostream_t os = pb_ostream_from_buffer(out, sizeof(out));
	if (!pb_encode(&os, ranz_control_v1_ControlMessage_fields, &msg)) {
		fprintf(stderr, "%s: encode: %s\n", path, PB_GET_ERROR(&os));
		return 0;
	}
	if (os.bytes_written != n || memcmp(in, out, n) != 0) {
		fprintf(stderr, "%s: %s: %zu bytes in, %zu bytes out, not the same\n", path, body_name(msg.which_body), n,
				os.bytes_written);
		return 0;
	}

	switch (msg.which_body) {
	case ranz_control_v1_ControlMessage_update_tag:
		printf("%s: Update generation %llu base %llu, %u set, %u remove, %zu bytes\n", path,
			   (unsigned long long)msg.body.update.generation, (unsigned long long)msg.body.update.base_generation,
			   (unsigned)msg.body.update.set_count, (unsigned)msg.body.update.remove_count, n);
		break;
	case ranz_control_v1_ControlMessage_hello_tag:
		printf("%s: Hello schema %d applied %llu", path, (int)msg.body.hello.schema_version,
			   (unsigned long long)msg.body.hello.applied_generation);
		if (msg.body.hello.has_capabilities) {
			const ranz_control_v1_Capabilities *c = &msg.body.hello.capabilities;
			printf(", Capabilities sku %d architecture %d egress tier %d xdp %d selow %d", (int)c->sku,
				   (int)c->architecture, (int)c->egress_tier, (int)c->xdp, (int)c->selow);
		}
		printf("\n");
		break;
	case ranz_control_v1_ControlMessage_ack_tag:
		printf("%s: Ack generation %llu\n", path, (unsigned long long)msg.body.ack.generation);
		break;
	case ranz_control_v1_ControlMessage_refuse_tag:
		printf("%s: Refuse %d \"%s\" leader \"%s\"\n", path, (int)msg.body.refuse.reason, msg.body.refuse.message,
			   msg.body.refuse.leader);
		break;
	case ranz_control_v1_ControlMessage_controllers_tag:
		printf("%s: Controllers, %u members\n", path, (unsigned)msg.body.controllers.controllers_count);
		break;
	case ranz_control_v1_ControlMessage_signal_tag:
		printf("%s: Signal peer \"%s\", %u bytes of envelope\n", path, msg.body.signal.peer, (unsigned)msg.body.signal.envelope.size);
		break;
	case ranz_control_v1_ControlMessage_telemetry_tag:
		printf("%s: Telemetry, %u peers, %u VRFs, %u rules, %u flows, %u events, %zu bytes\n", path, (unsigned)msg.body.telemetry.peers_count,
			   (unsigned)msg.body.telemetry.vrfs_count, (unsigned)msg.body.telemetry.rules_count, (unsigned)msg.body.telemetry.flows_count,
			   (unsigned)msg.body.telemetry.events_count, n);
		break;
	case ranz_control_v1_ControlMessage_leases_tag:
		printf("%s: Leases of \"%s\", %u leases, %zu bytes\n", path, msg.body.leases.network, (unsigned)msg.body.leases.leases_count, n);
		break;
	case ranz_control_v1_ControlMessage_operation_tag:
		printf("%s: Operation %llu of kind %d on \"%s\", %zu bytes\n", path, (unsigned long long)msg.body.operation.id,
			   (int)msg.body.operation.kind, msg.body.operation.network, n);
		break;
	case ranz_control_v1_ControlMessage_operation_result_tag:
		printf("%s: OperationResult %llu of status %d, %u entries of %u, %zu bytes\n", path, (unsigned long long)msg.body.operation_result.id,
			   (int)msg.body.operation_result.status, (unsigned)msg.body.operation_result.entries_count,
			   (unsigned)msg.body.operation_result.total, n);
		break;
	case ranz_control_v1_ControlMessage_pins_tag:
		printf("%s: Pins, a mimic key of %u bytes, %zu bytes\n", path, (unsigned)msg.body.pins.mimic_key.size, n);
		break;
	default:
		fprintf(stderr, "%s: a control message with no body\n", path);
		return 0;
	}
	return 1;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: nanopb_roundtrip FILE...\n");
		return 2;
	}
	int failed = 0;
	for (int i = 1; i < argc; i++) {
		if (!roundtrip(argv[i])) {
			failed++;
		}
	}
	printf("%d of %d control messages round trip through nanopb\n", argc - 1 - failed, argc - 1);
	return failed == 0 ? 0 : 1;
}
