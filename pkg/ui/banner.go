package ui

import "strings"

const (
	reset        = "\033[0m"
	bold         = "\033[1m"
	wingWhite    = "\033[38;5;195m"
	outlineGray  = "\033[38;5;244m"
	beeYellow    = "\033[38;5;226m"
	honeyOrange  = "\033[38;5;214m"
	bodyAmber    = "\033[38;5;178m"
	bodyBrown    = "\033[38;5;94m"
	mint         = "\033[38;5;121m"
	seafoam      = "\033[38;5;49m"
	cobalt       = "\033[38;5;33m"
	deepIndigo   = "\033[38;5;61m"
	fuchsia      = "\033[38;5;177m"
	hotspotFlame = "\033[38;5;208m"
)

// Banner renders a colored hotspot wordmark.
func Banner() string {
	var b strings.Builder

	hotspotLetters := [][]string{
		{"██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
		{" ██████╗ ", "██╔═████╗", "██║██╔██║", "████╔╝██║", "╚██████╔╝", " ╚═════╝ "},
		{"████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "},
		{" ██████╗ ", "██╔════╝ ", "╚█████╗  ", " ╚═══██╗ ", "██████╔╝ ", "╚═════╝  "},
		{"██████╗  ", "██╔══██╗ ", "██████╔╝ ", "██╔═══╝  ", "██║      ", "╚═╝      "},
		{" ██████╗ ", "██╔═████╗", "██║██╔██║", "████╔╝██║", "╚██████╔╝", " ╚═════╝ "},
		{"████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "},
	}
	hotspotGradient := []string{hotspotFlame, honeyOrange, beeYellow, mint, cobalt, deepIndigo, fuchsia}
	hotspotRows := make([]string, len(hotspotLetters[0]))
	for i, letter := range hotspotLetters {
		color := hotspotGradient[i%len(hotspotGradient)]
		for row := 0; row < len(letter); row++ {
			hotspotRows[row] += color + letter[row] + "  "
		}
	}
	for _, line := range hotspotRows {
		b.WriteString(bold + line + reset + "\n")
	}

	b.WriteString("\n")
	b.WriteString(bold + hotspotFlame + "hotspot" + reset + "  •  eBPF performance lens\n\n")

	return b.String()
}
