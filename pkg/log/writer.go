// (c) go2rtc

package log

type LogWriter struct {
	Buf   []byte
	Log   bool
	Level string // Log level for filtering output: Info, Debug, Warn, Error, Fatal, Trace
	N     int
}

func (l *LogWriter) String() string {
	if l.N == len(l.Buf) {
		return string(l.Buf) + "..."
	}
	return string(l.Buf[:l.N])
}

func (l *LogWriter) Write(p []byte) (n int, err error) {
	if l.N < cap(l.Buf) {
		l.N += copy(l.Buf[l.N:], p)
	}
	n = len(p)
	if l.Log {
		if p = trimSpace(p); p != nil {
			switch l.Level {
			case "Info":
				Logger.Info().Msgf("[exec] %s", p)
			case "Debug":
				Logger.Debug().Msgf("[exec] %s", p)
			case "Warn":
				Logger.Warn().Msgf("[exec] %s", p)
			case "Error":
				Logger.Error().Msgf("[exec] %s", p)
			case "Fatal":
				Logger.Fatal().Msgf("[exec] %s", p)
			case "Trace":
				Logger.Trace().Msgf("[exec] %s", p)
			default:
				Logger.Debug().Msgf("[exec] %s", p) // Default to Info if no level specified
			}
		}
	}
	return
}

func trimSpace(b []byte) []byte {
	start := 0
	stop := len(b)
	for ; start < stop; start++ {
		if b[start] >= ' ' {
			break // trim all ASCII before 0x20
		}
	}
	for ; ; stop-- {
		if stop == start {
			return nil // skip empty output
		}
		if b[stop-1] > ' ' {
			break // trim all ASCII before 0x21
		}
	}
	return b[start:stop]
}
