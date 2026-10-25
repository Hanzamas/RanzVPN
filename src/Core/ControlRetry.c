// ControlRetry.c
// The delay before a client of the control stream opens its stream again (SDN-90, #395). A stream that was open and was
// not refused ended because the controller or the network went: the client dials again after CONTROL_RETRY. Each attempt
// that fails after it, a dial that no controller answers, a TLS session or a certificate that fails its check, a Noise
// handshake that fails or a controller that refuses the node, doubles the delay, up to CONTROL_RETRY_MAX. So a Node whose
// controller is gone for a while, or that the controller does not know yet, dials less and less often and never stops,
// and it joins by itself once the controller is back or an operator has written its Node resource.

#include "Core/Control.h"

UINT ControlRetryNext(UINT delay, UINT end) {
	if (end == CONTROL_END_CLOSED || delay < CONTROL_RETRY)
		return CONTROL_RETRY;

	return (delay >= CONTROL_RETRY_MAX / 2 ? CONTROL_RETRY_MAX : delay * 2);
}
