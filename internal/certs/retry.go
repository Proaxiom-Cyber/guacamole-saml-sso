package certs

import (
	"net/http"
	"strconv"
	"time"
)

// Rate limits need an operator-visible result, not a sleep lasting hours.
// Brief transient failures may retry, respecting the server's minimum delay.
func certificateRetryBackoff(attempt int, _ *http.Request, response *http.Response) time.Duration {
	if response.StatusCode == http.StatusTooManyRequests || attempt > 3 {
		return 0
	}
	delay := time.Duration(1<<uint(max(0, min(attempt-1, 3)))) * time.Second
	if value := response.Header.Get("Retry-After"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil {
			if seconds > 10 {
				return 0
			}
			delay = max(delay, time.Duration(seconds)*time.Second)
		} else if when, err := http.ParseTime(value); err == nil {
			wait := time.Until(when)
			if wait > 10*time.Second {
				return 0
			}
			delay = max(delay, wait)
		}
	}
	return delay
}
