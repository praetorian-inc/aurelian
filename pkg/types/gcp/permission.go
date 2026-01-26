package gcptypes

type Provenance struct {
	ViaContainers []string
	ViaRoles      []string
	IsConditional bool
	Conditions    []string
}

type ContainsEdge struct {
	Parent *Resource
	Child  *Resource
}

type PermissionTuple struct {
	Source     *Resource
	Permission Permission
	Target     *Resource
	Provenance *Provenance
	IsDeny     bool
}

type PermissionSet map[Permission]struct{}

func NewPermissionSet() PermissionSet {
	return make(PermissionSet)
}

func (ps PermissionSet) Add(p Permission) {
	ps[p] = struct{}{}
}

func (ps PermissionSet) Contains(p Permission) bool {
	_, ok := ps[p]
	return ok
}

func (ps PermissionSet) Union(other PermissionSet) PermissionSet {
	result := NewPermissionSet()
	for p := range ps {
		result.Add(p)
	}
	for p := range other {
		result.Add(p)
	}
	return result
}

func (ps PermissionSet) Subtract(other PermissionSet) PermissionSet {
	result := NewPermissionSet()
	for p := range ps {
		if !other.Contains(p) {
			result.Add(p)
		}
	}
	return result
}

func (ps PermissionSet) ToSlice() []Permission {
	result := make([]Permission, 0, len(ps))
	for p := range ps {
		result = append(result, p)
	}
	return result
}
