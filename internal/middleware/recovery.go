package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/fabricio948/system_login/internal/httpx"
)

// Recovery converts panics into JSON 500 responses and logs the stack.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				if logger != nil {
					logger.Error("panic recovered",
						"error", recovered,
						"method", r.Method,
						"path", r.URL.Path,
						"stack", string(debug.Stack()),
					)
				}
				httpx.WriteJSONError(w, http.StatusInternalServerError,
					"internal_error", "internal server error")
			}()

			next.ServeHTTP(w, r)
		})
	}
}
