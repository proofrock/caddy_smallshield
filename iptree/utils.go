package iptree

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const retriesNumber int = 3
const retryPause time.Duration = 2 * time.Second

func fetchBodyLinesWithRetries(url string) ([]string, error) {
	var err error
	var body []byte

	for i := 0; i < retriesNumber; i++ { // First attempt + n retries
		var resp *http.Response
		resp, err = http.Get(url)
		if err != nil {
			if i < retriesNumber-1 { // Pause only for the first n-1 attempts
				time.Sleep(retryPause)
			}
			continue
		}

		// Check HTTP status code
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			err = errors.New("failed to fetch URL, status code: " + resp.Status)
			if i < retriesNumber-1 {
				time.Sleep(retryPause)
			}
			continue
		}

		// Read the body
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {

			return strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n"), nil
		}

		// Pause before retrying if body read failed
		if i < retriesNumber-1 {
			time.Sleep(retryPause)
		}
	}

	// Return the last error if all attempts fail
	return nil, err
}
