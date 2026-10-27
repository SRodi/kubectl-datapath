package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/SRodi/kubectl-datapath/internal/model"
	traceview "github.com/SRodi/kubectl-datapath/internal/trace"
)

// ringBufferBytes mirrors the events ring buffer size in bpf/datapath.c.
const ringBufferBytes = 1 << 20

const (
	stateOK          = "ok"
	stateIdle        = "idle"
	stateGap         = "gap"
	stateLost        = "lost"
	stateStarting    = "starting"
	stateUnavailable = "unavailable"

	stripSegment = 17
	// Five points need about 100 columns; below that the strip is vertical.
	stripMinWidth = 104
)

var (
	idleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("45"))
	gapStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

type stripPoint struct {
	label    string
	state    string
	iface    string
	hook     string
	isIntent bool
	seen     uint64
	captured uint64
	counted  bool
}

type stripSummary struct {
	badge    string
	glyph    string
	style    lipgloss.Style
	headline string
	detail   string
}

func pointState(point traceview.EvidencePoint) string {
	switch point.State {
	case "OBSERVED":
		return stateOK
	case "NO EVIDENCE":
		return stateGap
	case "INCOMPLETE":
		return stateLost
	case "NOT READY":
		return stateStarting
	default:
		return stateUnavailable
	}
}

func stateGlyph(state string) string {
	switch state {
	case stateOK:
		return "●"
	case stateIdle:
		return "◇"
	case stateGap:
		return "×"
	case stateLost:
		return "!"
	default:
		return "○"
	}
}

func stateStyle(state string) lipgloss.Style {
	switch state {
	case stateOK:
		return exactStyle
	case stateIdle:
		return idleStyle
	case stateGap:
		return gapStyle
	case stateLost:
		return warnStyle
	default:
		return subtleStyle
	}
}

func attachmentCounts(attachment model.Observation) (seen, captured uint64) {
	for _, counters := range attachment.Diagnostics {
		seen += counters.Seen
		captured += counters.Emitted
	}
	return seen, captured
}

func hookFamily(attachment model.Observation) string {
	if len(attachment.Hooks) == 0 {
		return ""
	}
	family, _, _ := strings.Cut(attachment.Hooks[0], "/")
	return family
}

// Pod boundary observations may be packets, so prefer the matching status record.
func resolveAttachment(selected model.Observation, attachments []model.Observation) model.Observation {
	if selected.AttachmentID == "" {
		return selected
	}
	for _, attachment := range attachments {
		if attachment.AttachmentID == selected.AttachmentID {
			return attachment
		}
	}
	return selected
}

func transitAttachment(attachments []model.Observation, side, node string) model.Observation {
	for _, attachment := range attachments {
		if attachment.Side == side && attachment.Node == node {
			return attachment
		}
	}
	return model.Observation{}
}

func newStripPoint(label string, evidence traceview.EvidencePoint, attachment model.Observation) stripPoint {
	point := stripPoint{label: label, state: pointState(evidence), iface: attachment.Interface, hook: hookFamily(attachment)}
	if attachment.AttachmentID != "" && len(attachment.Diagnostics) > 0 {
		point.seen, point.captured = attachmentCounts(attachment)
		point.counted = true
	}
	return point
}

func buildStrip(
	datapath traceview.DatapathView,
	attachments []model.Observation,
	podPackets uint64,
	closed bool,
) []stripPoint {
	var points []stripPoint
	if datapath.Connect != nil {
		connect := newStripPoint("connect", *datapath.Connect, model.Observation{})
		connect.iface, connect.hook, connect.isIntent = "fentry", "", true
		points = append(points, connect)
	}
	points = append(points, newStripPoint("src Pod", datapath.SourceBoundary,
		resolveAttachment(datapath.SourceInterface, attachments)))
	if datapath.CrossNode {
		points = append(points,
			newStripPoint("src node", dereferencePoint(datapath.SourceTransit),
				transitAttachment(attachments, "transit-source", datapath.SourceNode)),
			newStripPoint("dst node", dereferencePoint(datapath.DestinationTransit),
				transitAttachment(attachments, "transit-destination", datapath.DestinationNode)),
		)
	}
	points = append(points, newStripPoint("dst Pod", datapath.DestinationBoundary,
		resolveAttachment(datapath.DestinationInterface, attachments)))

	// "No evidence" only means a gap once traffic has been judged; before that
	// the hook is simply attached and idle.
	judged := podPackets > 0 || closed
	for _, point := range points {
		if !point.isIntent && point.state == stateOK {
			judged = true
		}
	}
	for index := range points {
		if points[index].state == stateGap && !judged {
			points[index].state = stateIdle
		}
	}
	return points
}

func summarize(points []stripPoint, datapath traceview.DatapathView, streamErr, closed bool) stripSummary {
	has := func(state string) (stripPoint, bool) {
		for _, point := range points {
			if point.state == state {
				return point, true
			}
		}
		return stripPoint{}, false
	}
	if streamErr {
		return stripSummary{
			badge: "INCOMPLETE", glyph: "!", style: warnStyle,
			headline: "Capture stream failed", detail: datapath.Diagnosis,
		}
	}
	if lost, ok := has(stateLost); ok {
		return stripSummary{
			badge: "INCOMPLETE", glyph: "!", style: warnStyle,
			headline: "Events lost at " + lost.label, detail: datapath.Diagnosis,
		}
	}
	// Evidence at the destination proves the path even if an intermediate
	// capture point is not ready or not instrumented.
	reached := len(points) > 0 && points[len(points)-1].state == stateOK
	if _, ok := has(stateStarting); ok && !reached {
		return stripSummary{
			badge: "STARTING", glyph: "○", style: subtleStyle,
			headline: "Waiting for capture points to attach…", detail: datapath.Diagnosis,
		}
	}
	if unavailable, ok := has(stateUnavailable); ok && !reached {
		return stripSummary{
			badge: "INCOMPLETE", glyph: "○", style: warnStyle,
			headline: unavailable.label + " is not instrumented", detail: datapath.Diagnosis,
		}
	}
	if _, ok := has(stateIdle); ok && !reached {
		return stripSummary{
			badge: "WAITING", glyph: "◇", style: idleStyle,
			headline: "Waiting for traffic…",
			detail:   "Hooks are attached; no matching traffic has been seen yet.",
		}
	}
	if gap, ok := has(stateGap); ok && !reached {
		headline := "No matching evidence at " + gap.label
		for index, point := range points {
			if point.state == stateGap && index > 0 && points[index-1].state == stateOK {
				headline = "Evidence stops before " + point.label
				break
			}
		}
		return stripSummary{
			badge: "GAP FOUND", glyph: "×", style: gapStyle,
			headline: headline, detail: datapath.Diagnosis,
		}
	}
	headline := "Observed at every point"
	for _, point := range points {
		if point.state != stateOK {
			headline = "Observed through " + points[len(points)-1].label
			break
		}
	}
	badge := "OBSERVED"
	if closed {
		badge = "COMPLETE"
	}
	return stripSummary{
		badge: badge, glyph: "●", style: exactStyle,
		headline: headline, detail: datapath.Diagnosis,
	}
}

func formatCount(value uint64) string {
	digits := fmt.Sprint(value)
	for index := len(digits) - 3; index > 0; index -= 3 {
		digits = digits[:index] + "," + digits[index:]
	}
	return digits
}

func pad(value string, width int) string {
	return lipgloss.NewStyle().Width(width).Render(truncate(value, width-1))
}

func linkFor(left, right string) (string, lipgloss.Style) {
	glyph := "┈"
	switch {
	case left == stateOK && right == stateOK:
		glyph = "━"
		return strings.Repeat(glyph, stripSegment-1), exactStyle
	case left == stateOK && (right == stateGap || right == stateLost):
		return strings.Repeat(glyph, stripSegment-1), gapStyle
	case left == stateIdle || right == stateIdle:
		return strings.Repeat("┄", stripSegment-1), idleStyle
	}
	return strings.Repeat(glyph, stripSegment-1), subtleStyle
}

func pointDetail(point stripPoint) (interfaceLine, seenLine, capturedLine string) {
	interfaceLine = strings.TrimSpace(point.iface + " " + point.hook)
	switch {
	case point.state == stateStarting:
		return interfaceLine, "not ready", ""
	case point.state == stateUnavailable:
		return interfaceLine, "unavailable", ""
	case point.state == stateIdle:
		capturedLine = "attached, idle"
	case point.isIntent && point.state == stateOK:
		capturedLine = "intent seen"
	case point.isIntent:
		capturedLine = "no intent seen"
	}
	if point.counted {
		seenLine = "seen " + formatCount(point.seen)
		if capturedLine == "" {
			capturedLine = "captured " + formatCount(point.captured)
		}
	}
	return interfaceLine, seenLine, capturedLine
}

func renderStrip(points []stripPoint, width int) string {
	if width > 0 && width < stripMinWidth {
		return renderVerticalStrip(points)
	}
	var labels, markers, interfaces, seen, captured strings.Builder
	for index, point := range points {
		style := stateStyle(point.state)
		interfaceLine, seenLine, capturedLine := pointDetail(point)
		labels.WriteString(pad(point.label, stripSegment))
		interfaces.WriteString(pad(interfaceLine, stripSegment))
		seen.WriteString(pad(seenLine, stripSegment))
		captured.WriteString(pad(capturedLine, stripSegment))
		markers.WriteString(style.Bold(true).Render(stateGlyph(point.state)))
		if index < len(points)-1 {
			link, linkStyle := linkFor(point.state, points[index+1].state)
			markers.WriteString(linkStyle.Render(link))
		}
	}
	lines := []string{
		"  " + subtleStyle.Render(strings.TrimRight(labels.String(), " ")),
		"  " + markers.String(),
		"  " + subtleStyle.Render(strings.TrimRight(interfaces.String(), " ")),
		"  " + subtleStyle.Render(strings.TrimRight(seen.String(), " ")),
		"  " + subtleStyle.Render(strings.TrimRight(captured.String(), " ")),
	}
	return strings.Join(lines, "\n")
}

func renderVerticalStrip(points []stripPoint) string {
	var lines []string
	for index, point := range points {
		interfaceLine, seenLine, capturedLine := pointDetail(point)
		var parts []string
		for _, part := range []string{interfaceLine, seenLine, capturedLine} {
			if part != "" {
				parts = append(parts, part)
			}
		}
		lines = append(lines, fmt.Sprintf("  %s %s %s",
			stateStyle(point.state).Bold(true).Render(stateGlyph(point.state)),
			pad(point.label, 9), subtleStyle.Render(strings.Join(parts, " · "))))
		if index < len(points)-1 {
			glyph := "┊"
			style := subtleStyle
			switch {
			case point.state == stateOK && points[index+1].state == stateOK:
				glyph, style = "┃", exactStyle
			case point.state == stateOK:
				style = gapStyle
			case point.state == stateIdle || points[index+1].state == stateIdle:
				glyph, style = "┆", idleStyle
			}
			lines = append(lines, "  "+style.Render(glyph))
		}
	}
	return strings.Join(lines, "\n")
}

func wrap(value string, width int) string {
	if width <= 0 {
		return value
	}
	return lipgloss.NewStyle().Width(max(20, width)).Render(value)
}

func indent(value string) string {
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		lines[index] = "  " + strings.TrimRight(line, " ")
	}
	return strings.Join(lines, "\n")
}

func stripLegend() string {
	return "● observed  ◇ attached, idle  × attached, no matching evidence  ! incomplete  ○ not ready/unavailable"
}
