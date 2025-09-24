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
