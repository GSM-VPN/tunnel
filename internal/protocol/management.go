package protocol

// ManagementVersion is the version of the Go-Rust control-plane message format.
const ManagementVersion uint16 = 1

// Operation identifies a controller request without carrying data-plane keys.
type Operation uint16

const (
	OperationHealth Operation = iota + 1
	OperationStart
	OperationStop
	OperationGetMetrics
)

// ManagementRequest contains only control-plane metadata and opaque operation payload.
// Key material must never be represented by this type.
type ManagementRequest struct {
	Version   uint16
	RequestID uint64
	Operation Operation
	Payload   []byte
}

// ManagementResponse contains a request result and an optional operation payload.
type ManagementResponse struct {
	Version   uint16
	RequestID uint64
	Status    uint16
	ErrorCode uint16
	Payload   []byte
}
