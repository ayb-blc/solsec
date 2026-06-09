// internal/trace/builder.go

package trace

// Builder constructs a Trace fluently.
// Each Add* method appends one step and returns the builder.
type Builder struct {
	t Trace
}

// NewBuilder creates an empty Builder with an optional summary.
func NewBuilder(summary string) *Builder {
	return &Builder{t: Trace{Summary: summary}}
}

// Build finalises and returns the Trace.
func (b *Builder) Build() *Trace {
	t := b.t
	return &t
}

// ── step adders ───────────────────────────────────────────────────────────────

func (b *Builder) Read(detail string, loc Location, note string) *Builder {
	return b.add(KindRead, detail, loc, note, false)
}

func (b *Builder) Write(detail string, loc Location, note string) *Builder {
	return b.add(KindWrite, detail, loc, note, false)
}

func (b *Builder) WriteIssue(detail string, loc Location, note string) *Builder {
	return b.add(KindWrite, detail, loc, note, true)
}

func (b *Builder) Call(detail string, loc Location, note string) *Builder {
	return b.add(KindExternalCall, detail, loc, note, false)
}

func (b *Builder) CallIssue(detail string, loc Location, note string) *Builder {
	return b.add(KindExternalCall, detail, loc, note, true)
}

func (b *Builder) Inherits(detail string, loc Location, note string) *Builder {
	return b.add(KindInherits, detail, loc, note, false)
}

func (b *Builder) Override(detail string, loc Location, note string) *Builder {
	return b.add(KindOverride, detail, loc, note, false)
}

func (b *Builder) OverrideIssue(detail string, loc Location, note string) *Builder {
	return b.add(KindOverride, detail, loc, note, true)
}

func (b *Builder) Modifier(detail string, loc Location, note string) *Builder {
	return b.add(KindModifier, detail, loc, note, false)
}

func (b *Builder) Missing(detail string, loc Location, note string) *Builder {
	return b.add(KindMissing, detail, loc, note, true)
}

func (b *Builder) Effect(detail string, loc Location, note string) *Builder {
	return b.add(KindEffect, detail, loc, note, false)
}

func (b *Builder) Info(detail string, loc Location, note string) *Builder {
	return b.add(KindInfo, detail, loc, note, false)
}

func (b *Builder) add(
	kind StepKind, detail string, loc Location,
	note string, isIssue bool,
) *Builder {
	b.t.Steps = append(b.t.Steps, Step{
		Kind:     kind,
		Detail:   detail,
		Location: loc,
		Note:     note,
		IsIssue:  isIssue,
	})
	return b
}
