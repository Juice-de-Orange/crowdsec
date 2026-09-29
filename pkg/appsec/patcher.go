package appsec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/expr-lang/expr/ast"
)

type appsecExprPatcher struct {
	NeedWASMVM bool
	// A visitor returns nothing, so rejections are parked here and Hook.Build
	// turns the ones a given rule produced into its build error.
	Errs []string
}

// challengeRuntimeCallees is the set of expr helper names whose presence in
// any compiled rule body implies that the challenge runtime (WASM VM,
// obfuscator, keyring) must be initialized.
var challengeRuntimeCallees = map[string]struct{}{
	"SendChallenge":        {},
	"GrantChallengeCookie": {},
	"RejectSubmission":     {},
	"LogAccepted":          {},
	// no runtime, no cookie validation: the helper would always return false
	"HasValidChallengeCookie": {},
}

// Index of each helper's first category argument, counted as the rule author
// wrote the call. Omitting the argument is how you mean "no category", so an
// empty one is always a mistake: it would quietly match nothing.
var categoryArgFrom = map[string]int{
	"RequestScore":    0,
	"SetRequestScore": 1,
	"AddRequestScore": 2,
}

func (p *appsecExprPatcher) Visit(node *ast.Node) { //nolint:gocritic // signature fixed by expr-lang ast.Visitor interface
	n, ok := (*node).(*ast.CallNode)
	if !ok {
		return
	}

	callee := n.Callee.String()

	if _, needs := challengeRuntimeCallees[callee]; needs {
		p.NeedWASMVM = true
	}

	from, tracked := categoryArgFrom[callee]
	if !tracked {
		return
	}

	args := n.Arguments

	// expr.WithContext splices the hidden context argument in front before
	// this runs. Detect it rather than assuming, so the indices stay tied to
	// the source even if the option order changes.
	if len(args) > 0 {
		if id, isIdent := args[0].(*ast.IdentifierNode); isIdent && id.Value == scoreCtxVar {
			args = args[1:]
		}
	}

	for _, arg := range args[min(from, len(args)):] {
		s, isStr := arg.(*ast.StringNode)
		if !isStr || strings.TrimSpace(s.Value) != "" {
			continue
		}

		// A patcher can be walked over the same node more than once.
		msg := fmt.Sprintf("%s: empty category argument, omit it to mean no category", callee)
		if !slices.Contains(p.Errs, msg) {
			p.Errs = append(p.Errs, msg)
		}
	}
}
