package discover

// stripJSONC turns the JSON-with-comments that Zed and VS Code write into
// plain JSON: // and /* */ comments become whitespace and a comma right
// before a closing bracket is dropped. Strings are copied through
// untouched, so a "//" inside a value survives.
func stripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	n := len(in)
	for i := 0; i < n; i++ {
		c := in[i]
		switch {
		case c == '"':
			// Copy the string literal, escapes included.
			out = append(out, c)
			for i++; i < n; i++ {
				out = append(out, in[i])
				if in[i] == '\\' && i+1 < n {
					i++
					out = append(out, in[i])
					continue
				}
				if in[i] == '"' {
					break
				}
			}
		case c == '/' && i+1 < n && (in[i+1] == '/' || in[i+1] == '*'):
			i = skipTrivia(in, i) - 1
			out = append(out, ' ')
		case c == ',':
			if j := skipTrivia(in, i+1); j < n && (in[j] == ']' || in[j] == '}') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// skipTrivia returns the index of the first byte at or after i that is
// neither whitespace nor part of a comment.
func skipTrivia(in []byte, i int) int {
	n := len(in)
	for i < n {
		switch {
		case in[i] == ' ' || in[i] == '\t' || in[i] == '\n' || in[i] == '\r':
			i++
		case in[i] == '/' && i+1 < n && in[i+1] == '/':
			for i < n && in[i] != '\n' {
				i++
			}
		case in[i] == '/' && i+1 < n && in[i+1] == '*':
			i += 2
			for i+1 < n && (in[i] != '*' || in[i+1] != '/') {
				i++
			}
			i += 2
		default:
			return i
		}
	}
	return n
}
