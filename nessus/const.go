package nessus

const (
	xCookie  = "X-Cookie"
	xApiKeys = "X-ApiKeys"
)

type EditorType string

const (
	TypeScan   EditorType = "scan"
	TypePolicy EditorType = "policy"
)

type ScanStatus string

const (
	TypePending   ScanStatus = "pending"
	TypeRunning   ScanStatus = "running"
	TypePaused    ScanStatus = "paused"
	TypeStopping  ScanStatus = "stopping"
	TypeCanceled  ScanStatus = "canceled"
	ScanCompleted ScanStatus = "completed"
	ScanEmpty     ScanStatus = "empty"
	ScanAborted   ScanStatus = "aborted"
)
