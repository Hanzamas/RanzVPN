package event

// The types of the events that the source restrictions raise (SDN-39, #232), beside the one of
// event.go. Each is the record that an administrator reads of a refusal, or of a change of the
// restriction itself, with `ranz get events`.
const (
	// AdminAccessRefused: a request for the API or the web UI came from an address outside the
	// admin source allowlist and was refused.
	AdminAccessRefused = "admin-access-refused"
	// AdminSourcesChanged: an admin set the admin source allowlist or removed it.
	AdminSourcesChanged = "admin-sources-changed"
	// AdminDestinationsChanged: an admin set the admin destination lists (AUD1-DT-9, #457): the
	// hosts that targets may name, the sensor prefixes and the UNC servers.
	AdminDestinationsChanged = "admin-destinations-changed"
	// EnrolmentRefused: a node opened its control stream from an address outside the source
	// prefixes of a Network that it joins, and was refused.
	EnrolmentRefused = "enrolment-refused"
)
