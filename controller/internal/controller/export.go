package controller

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The export and the import of the whole intent (SDN-52, #245). An export is the intent as one
// document, with the values the controller filled in (the id and the ULA of each VRF); an import
// makes a document the whole intent as the next revision. Compiling depends on the intent and the
// licence in force alone (internal/desired), so an export imported into an empty controller gives
// every node the desired state it has in the controller the export came from.

// Export returns the whole intent as the document that Import takes (`ranz export`).
func (c *Controller) Export() intent.Document {
	c.mu.Lock()
	defer c.mu.Unlock()
	rs := c.intent.Resources()
	if rs == nil {
		rs = []intent.Resource{}
	}
	return intent.Document{Resources: rs}
}

// Import makes doc the whole intent as the next revision (`ranz import -f`): the resources of
// doc are applied as Apply applies them, and every resource that doc leaves out is deleted
// (intent.Replace). It is checked as an apply is, and a refused import changes nothing.
func (c *Controller) Import(ctx context.Context, doc intent.Document) (ApplyResult, error) {
	if err := c.known(doc.Resources); err != nil {
		return ApplyResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.unconfirmed(); err != nil {
		return ApplyResult{}, err
	}
	st := c.evaluate(c.lic)
	if err := c.checkCluster(ctx, st); err != nil {
		return ApplyResult{}, err
	}
	if err := checkFeatures(doc, st); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Replace(c.intent, doc, c.random)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := c.checkDestinations(ctx, next); err != nil {
		return ApplyResult{}, err
	}
	if err := c.checkCap(next, st, "import"); err != nil {
		return ApplyResult{}, err
	}
	cp, err := c.compile(next, c.lic)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := c.honoured(next, cp.states); err != nil {
		c.log.Warn("import refused: capability", "err", err)
		return ApplyResult{}, err
	}
	res, err := c.change(ctx, next, cp, c.nextRevision(intent.OpImport), store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	c.log.Info("intent imported", "revision", res.Revision, "resources", len(doc.Resources), "changed", len(res.Nodes))
	return res, nil
}
