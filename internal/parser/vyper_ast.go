package parser

import "encoding/json"

type VyperModule struct {
	// ASTType her zaman "Module"
	ASTType string `json:"ast_type"`

	Body []*VyperNode `json:"body"`

	LineNumberRange VyperLineRange `json:"lineno,omitempty"`
}

// VyperNode represents any node in the Vyper AST.
type VyperNode struct {
	ASTType string `json:"ast_type"`

	Name       string       `json:"name,omitempty"`
	Args       *VyperArgs   `json:"args,omitempty"`
	Body       []*VyperNode `json:"body,omitempty"`
	Decorators []*VyperNode `json:"decorator_list,omitempty"`
	Returns    *VyperNode   `json:"returns,omitempty"`
	IsInternal bool         `json:"is_internal,omitempty"`
	IsPayable  bool         `json:"is_payable,omitempty"`
	IsView     bool         `json:"is_pure,omitempty"`

	Target     *VyperNode `json:"target,omitempty"`
	Annotation *VyperNode `json:"annotation,omitempty"`
	Value      *VyperNode `json:"value,omitempty"`

	ID    string     `json:"id,omitempty"`
	Attr  string     `json:"attr,omitempty"`
	Slice *VyperNode `json:"slice,omitempty"`

	Func     *VyperNode   `json:"func,omitempty"`
	CallArgs []*VyperNode `json:"-"`
	Keywords []*VyperNode `json:"keywords,omitempty"`

	Test   *VyperNode   `json:"test,omitempty"`
	ThenBB []*VyperNode `json:"-"`
	ElseBB []*VyperNode `json:"orelse,omitempty"`
	Iter   *VyperNode   `json:"iter,omitempty"`

	// --- Assign/AugAssign ---
	Targets []*VyperNode `json:"targets,omitempty"`
	Op      string       `json:"op,omitempty"`

	// --- Literal ---
	NodeValue interface{} `json:"-"`

	// --- BinOp / Compare ---
	Left        *VyperNode   `json:"left,omitempty"`
	Right       *VyperNode   `json:"right,omitempty"`
	Comparators []*VyperNode `json:"comparators,omitempty"`
	Ops         []string     `json:"ops,omitempty"`

	// --- Log (emit equivalent) ---
	Keyword *VyperNode `json:"keyword,omitempty"`

	// Konum bilgisi
	LineNumberRange VyperLineRange `json:"lineno,omitempty"`
	ColOffset       int            `json:"col_offset,omitempty"`
	EndColOffset    int            `json:"end_col_offset,omitempty"`
}

func (v *VyperNode) UnmarshalJSON(data []byte) error {
	type rawVyperNode VyperNode
	var raw struct {
		rawVyperNode
		Args  json.RawMessage `json:"args"`
		Body  []*VyperNode    `json:"body,omitempty"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = VyperNode(raw.rawVyperNode)
	v.Body = raw.Body
	v.ThenBB = raw.Body

	if len(raw.Args) > 0 && string(raw.Args) != "null" {
		if v.ASTType == "FunctionDef" {
			var args VyperArgs
			if err := json.Unmarshal(raw.Args, &args); err == nil {
				v.Args = &args
			}
		} else {
			var args []*VyperNode
			if err := json.Unmarshal(raw.Args, &args); err == nil {
				v.CallArgs = args
			}
		}
	}
	if len(raw.Value) > 0 && string(raw.Value) != "null" {
		var child VyperNode
		if err := json.Unmarshal(raw.Value, &child); err == nil && child.ASTType != "" {
			v.Value = &child
		} else {
			var scalar interface{}
			if err := json.Unmarshal(raw.Value, &scalar); err == nil {
				v.NodeValue = scalar
			}
		}
	}
	return nil
}

type VyperArgs struct {
	Args     []*VyperNode `json:"args"`
	Defaults []*VyperNode `json:"defaults,omitempty"`
}

type VyperLineRange struct {
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

func (v *VyperNode) StartLine() int {
	return v.LineNumberRange.Start
}

func (v *VyperNode) IsFunctionDef() bool {
	return v.ASTType == "FunctionDef"
}

// Vyper'da state variable'lar module seviyesinde AnnAssign olarak gelir.
func (v *VyperNode) IsStateVar() bool {
	return v.ASTType == "AnnAssign" && v.Target != nil
}

// @nonreentrant, @external, @internal, @view, @pure, @payable
func (v *VyperNode) HasDecorator(name string) bool {
	for _, dec := range v.Decorators {
		if dec == nil {
			continue
		}
		if dec.ASTType == "Call" && dec.Func != nil {
			if dec.Func.ID == name || dec.Func.Attr == name {
				return true
			}
		}
		if dec.ASTType == "Name" && dec.ID == name {
			return true
		}
		if dec.ID == name {
			return true
		}
	}
	return false
}

func (v *VyperNode) IsExternalFunction() bool {
	return v.HasDecorator("external") || (!v.IsInternal && !v.HasDecorator("internal"))
}

func (v *VyperNode) IsNonreentrant() bool {
	return v.HasDecorator("nonreentrant")
}

func (v *VyperNode) IsRawCall() bool {
	if v.ASTType != "Call" || v.Func == nil {
		return false
	}
	dangerous := map[string]bool{
		"send":     true,
		"raw_call": true,
		"raw_log":  true,
	}
	return dangerous[v.Func.ID] || dangerous[v.Func.Attr]
}

func (v *VyperNode) TargetName() string {
	if v.Target == nil {
		return ""
	}
	if v.Target.ASTType == "Name" {
		return v.Target.ID
	}
	return ""
}
