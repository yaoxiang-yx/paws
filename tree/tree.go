package tree

func NewTree() AWSTree {
	tree := AWSTree{}
	tree.Audit = AuditData{}
	return tree
}

// AWSTree represents a complete picture of an AWS account scan.
type AWSTree struct {
	Audit AuditData `json:"audit"`
}
