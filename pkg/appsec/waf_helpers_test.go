package appsec

import (
	"context"
	"testing"
	"time"

	"github.com/expr-lang/expr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// TestBotChallengeHooksCompile guards the env maps: a hook referencing
// MatchKnownBot (global helper) and ExemptFromChallenge(reason) must compile in
// every phase exposing them.
func TestBotChallengeHooksCompile(t *testing.T) {
	for _, stage := range []hookStage{hookPreEval, hookPostEval, hookOnMatch} {
		h := &Hook{
			Filter: `MatchKnownBot(req.RemoteAddr, req.UserAgent(), req.URL.Path, "legit_bots/gptbot.json")`,
			Apply:  []string{`ExemptFromChallenge("gptbot")`},
		}
		require.NoError(t, h.Build(t.Context(), stage, nil), "stage %v", stage)
	}
}

// TestRequestScoreHooksCompile guards the score accumulator env entries: the
// four helpers must compile in every request phase. The filter also exercises
// the expr builtins the shipped threshold configs rely on to build a reject
// reason (string() over an int, join() over a []string).
func TestRequestScoreHooksCompile(t *testing.T) {
	stages := []hookStage{hookPreEval, hookPostEval, hookOnMatch, hookOnChallenge, hookOnChallengeSubmit}
	for _, stage := range stages {
		h := &Hook{
			Filter: `RequestScore() >= 45 && RequestScoreFor("cdp") > 0 && string(RequestScore()) != "" && join(RequestScoreReasons(), ",") != ""`,
			Apply:  []string{`AddRequestScore(15, "utc_timezone")`},
		}
		require.NoError(t, h.Build(t.Context(), stage, &appsecExprPatcher{}), "stage %v", stage)
	}
}

// on_load has no request state, so scoring there must fail at config load
// rather than silently no-op.
func TestRequestScoreHooksRejectedInOnLoad(t *testing.T) {
	h := &Hook{Apply: []string{`AddRequestScore(15, "utc_timezone")`}}
	require.Error(t, h.Build(t.Context(), hookOnLoad, &appsecExprPatcher{}))
}

// The accumulator is plain Go state: referencing it must not drag the
// challenge runtime (WASM VM, obfuscator, keyring) into existence.
func TestRequestScoreDoesNotNeedChallengeRuntime(t *testing.T) {
	patcher := &appsecExprPatcher{}
	h := &Hook{
		Filter: `RequestScore() >= 45`,
		Apply:  []string{`AddRequestScore(15, "utc_timezone")`},
	}
	require.NoError(t, h.Build(t.Context(), hookPreEval, patcher))
	assert.False(t, patcher.NeedWASMVM)
}

// scoringStages are the phases that expose the request-score family. on_load
// is deliberately absent: see TestRequestScoreHooksRejectedInOnLoad.
var scoringStages = []hookStage{hookPreEval, hookPostEval, hookOnMatch, hookOnChallenge, hookOnChallengeSubmit}

func scoreEnvForStage(stage hookStage, w *AppsecRuntimeConfig, state *AppsecRequestState, req *ParsedRequest) map[string]any {
	ctx := context.Background()

	switch stage {
	case hookPreEval:
		return GetPreEvalEnv(ctx, w, state, req)
	case hookPostEval:
		return GetPostEvalEnv(ctx, w, state, req)
	case hookOnMatch:
		return GetOnMatchEnv(ctx, w, state, req, pipeline.Event{})
	case hookOnChallenge:
		return GetOnChallengeEnv(ctx, w, state, req)
	case hookOnChallengeSubmit:
		return GetOnChallengeSubmitEnv(ctx, w, state, req)
	case hookOnLoad:
		return GetOnLoadEnv(w)
	}

	return nil
}

// The score helpers are expr.Function, so they reach the request through the
// context rather than a closure. That wiring is per stage and easy to forget
// when a phase is added, so every scoring stage is driven end to end here:
// compile the rule, run it, and check the real state moved.
func TestRequestScoreHelpersBindStateInEveryStage(t *testing.T) {
	for _, stage := range scoringStages {
		t.Run(stage.String(), func(t *testing.T) {
			w := makeRuntime()
			state := &AppsecRequestState{HookVars: map[string]string{}}
			req := &ParsedRequest{}

			h := &Hook{Apply: []string{
				`AddRequestScore(100, "cdp", "fingerprint")`,
				`AddRequestScore(15, "utc_timezone")`,
				`SetRequestScore(5, "fingerprint")`,
			}}
			require.NoError(t, h.Build(t.Context(), stage, &appsecExprPatcher{}))

			env := scoreEnvForStage(stage, w, state, req)
			for _, program := range h.ApplyExpr {
				_, err := expr.Run(program, env)
				require.NoError(t, err)
			}

			// 100 in "fingerprint" replaced by 5, plus the uncategorized 15
			assert.Equal(t, 20, state.RequestScore.Total())
			assert.Equal(t, 5, state.RequestScore.ForCategories("fingerprint"))
			assert.Equal(t, 15, state.RequestScore.Uncategorized())
			assert.Equal(t, "20", state.HookVars[hookVarRequestScore])
		})
	}
}

// The prototypes are the contract rule authors write against: a wrong type or
// arity must fail at config load, not on the first live request, where the
// error would abort the whole hook chain.
func TestRequestScorePrototypes(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr string
	}{
		{name: "add without category", expr: `AddRequestScore(10, "cdp")`},
		{name: "add with category", expr: `AddRequestScore(10, "cdp", "bot")`},
		{name: "add rejects a second category", expr: `AddRequestScore(10, "cdp", "bot", "x")`, wantErr: "too many arguments"},
		// With two prototypes registered, expr reports any mismatch as an
		// arity error rather than naming the offending type. Still a config
		// load failure, just a blunter message.
		{name: "add rejects a non-string label", expr: `AddRequestScore(10, 5)`, wantErr: "arguments to call AddRequestScore"},
		{name: "score with no category", expr: `RequestScore() > 0`},
		{name: "score with one category", expr: `RequestScore("bot") > 0`},
		{name: "score with many categories", expr: `RequestScore("bot", "fingerprint") > 0`},
		{name: "score rejects a non-string category", expr: `RequestScore(1) > 0`, wantErr: "cannot use int"},
		{name: "set with no category", expr: `SetRequestScore(50)`},
		{name: "set with one category", expr: `SetRequestScore(50, "bot")`},
		{name: "set with many categories", expr: `SetRequestScore(50, "bot", "fingerprint")`},
		{name: "set requires a value", expr: `SetRequestScore("bot")`, wantErr: "cannot use string"},
		{name: "uncategorized takes no argument", expr: `RequestScoreUncategorized() > 0`},

		// Omitting the category is how you mean "no category"; an empty one
		// would match nothing, so it is a mistake worth catching at load.
		{name: "add rejects an empty category", expr: `AddRequestScore(10, "cdp", "")`, wantErr: "empty category argument"},
		{name: "score rejects an empty category", expr: `RequestScore("") > 0`, wantErr: "empty category argument"},
		{name: "score rejects a blank category", expr: `RequestScore("  ") > 0`, wantErr: "empty category argument"},
		{name: "set rejects an empty category", expr: `SetRequestScore(50, "")`, wantErr: "empty category argument"},
		{name: "set rejects an empty category among others", expr: `SetRequestScore(50, "bot", "")`, wantErr: "empty category argument"},
		// An empty *label* is long-standing behaviour: it normalizes to
		// "unspecified" rather than failing the load.
		{name: "add still accepts an empty label", expr: `AddRequestScore(10, "")`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Hook{Apply: []string{tc.expr}}).Build(t.Context(), hookPreEval, &appsecExprPatcher{})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestExemptFromChallengeSetsFlag verifies ExemptFromChallenge(reason) flips the
// per-request ChallengeExempt flag (which SendChallenge later honors), and that
// the flag is per-request state.
func TestExemptFromChallengeSetsFlag(t *testing.T) {
	state := &AppsecRequestState{HookVars: map[string]string{}}
	env := GetPreEvalEnv(t.Context(), &AppsecRuntimeConfig{}, state, &ParsedRequest{})

	exempt := env["ExemptFromChallenge"].(func(string) error)

	assert.False(t, state.ChallengeExempt)
	require.NoError(t, exempt("gptbot"))
	assert.True(t, state.ChallengeExempt)

	// per-request state: a fresh state starts clean
	fresh := &AppsecRequestState{HookVars: map[string]string{}}
	_ = GetPreEvalEnv(t.Context(), &AppsecRuntimeConfig{}, fresh, &ParsedRequest{})
	assert.False(t, fresh.ChallengeExempt)
}

// TestParseChallengeCookieTTLArg covers the GrantChallengeCookie optional TTL
// argument parsing: no args / empty string yield a nil override (use runtime
// default), a parseable duration yields a positive pointer, and malformed /
// non-positive / multi-arg inputs surface as errors so hook authors see a
// precise diagnostic instead of silent fallback.
func TestParseChallengeCookieTTLArg(t *testing.T) {
	t.Run("no args → nil override", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty string → nil override", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg([]string{""})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("valid duration", func(t *testing.T) {
		got, err := parseChallengeCookieTTLArg([]string{"1h30m"})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, 90*time.Minute, *got)
	})

	t.Run("malformed duration", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"forever"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid GrantChallengeCookie TTL")
	})

	t.Run("non-positive duration", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"-5m"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("multiple TTL args rejected", func(t *testing.T) {
		_, err := parseChallengeCookieTTLArg([]string{"1h", "2h"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most one TTL argument")
	})
}

// One patcher instance is reused across every hook in a list, so a rejection
// found in one rule must not fail the rules compiled after it.
func TestEmptyCategoryRejectionIsPerRule(t *testing.T) {
	patcher := &appsecExprPatcher{}

	bad := &Hook{Apply: []string{`AddRequestScore(10, "cdp", "")`}}
	require.Error(t, bad.Build(t.Context(), hookPreEval, patcher))

	good := &Hook{Apply: []string{`AddRequestScore(10, "cdp", "fingerprint")`}}
	require.NoError(t, good.Build(t.Context(), hookPreEval, patcher), "a later rule must not inherit the earlier rejection")

	alsoBad := &Hook{Apply: []string{`SetRequestScore(5, "")`}}
	require.Error(t, alsoBad.Build(t.Context(), hookPreEval, patcher))
}

// The load-time check only sees literals. A category that evaluates to empty
// at runtime has to degrade to "no such category" — returning 0 — rather than
// error, because an error here would abort the whole hook chain.
func TestEmptyCategoryFromVariableScoresZero(t *testing.T) {
	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}
	require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))

	h := &Hook{Filter: `RequestScore(hook_vars["never_set"])`}
	require.NoError(t, h.Build(t.Context(), hookPostEval, &appsecExprPatcher{}))

	env := scoreEnvForStage(hookPostEval, w, state, &ParsedRequest{})

	got, err := expr.Run(h.FilterExpr, env)
	require.NoError(t, err, "an empty category must not abort the hook chain")
	assert.Equal(t, 0, got)
}
