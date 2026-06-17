package detectors

import "strings"

func functionBodyForPathTracking(lines []string) []string {
	var body []string
	inBody := false
	depth := 0

	for _, line := range lines {
		if !inBody {
			open := strings.Index(line, "{")
			if open < 0 {
				continue
			}
			inBody = true
			depth += strings.Count(line, "{")
			depth -= strings.Count(line, "}")

			rest := strings.TrimSpace(line[open+1:])
			if rest != "" && rest != "}" {
				body = append(body, rest)
			}
			if depth <= 0 {
				break
			}
			continue
		}

		depth += strings.Count(line, "{")
		depth -= strings.Count(line, "}")

		trimmed := strings.TrimSpace(line)
		if depth <= 0 && (trimmed == "" || trimmed == "}") {
			break
		}
		body = append(body, line)
		if depth <= 0 {
			break
		}
	}

	if len(body) == 0 {
		return lines
	}
	return body
}
