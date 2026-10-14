package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"ovara.proxy/internal/gateway"
)

// claimNote says once that the gateway has no claim route.
var claimNote sync.Once

// settleApproval is what every poller does with an approval's status before
// acting on it: "approved" becomes "approved" only once the approval is
// claimed, so the action it allows runs once; "used" when an identical
// request took it first (the caller refuses and the agent asks again);
// "error" when the claim could not be made. Other statuses pass through. A
// gateway without the claim route (an older one) is noted once and the
// approval taken as before.
func settleApproval(ctx context.Context, gw *gateway.Client, id, status string) string {
	if status != approvalApprovedStatus {
		return status
	}
	_, claimed, err := gw.ClaimApproval(ctx, id)
	switch {
	case errors.Is(err, gateway.ErrClaimUnsupported):
		claimNote.Do(func() {
			fmt.Fprintln(os.Stderr, "[ovara] the gateway has no approval claim route: an approval is not single-use until it is upgraded")
		})
		return approvalApprovedStatus
	case err != nil:
		fmt.Fprintf(os.Stderr, "[ovara] claim approval %s: %v\n", id, err)
		return "error"
	case !claimed:
		fmt.Fprintf(os.Stderr, "[ovara] approval %s was already used by an identical request; it has to be asked again\n", id)
		return "used"
	}
	return approvalApprovedStatus
}
