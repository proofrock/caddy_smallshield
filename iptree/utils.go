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

func fetchBodyLines(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch URL, status code: " + resp.Status)
	}
	bbody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(bbody), "\n"), nil
}

func fetchBodyLinesWithRetries(url string) ([]string, error) {
	for i := 0; i < retriesNumber; i++ {
		ret, err := fetchBodyLines(url)
		if err == nil {
			return ret, nil
		}

		if i == retriesNumber-1 { // last retry
			return nil, err
		}

		time.Sleep(retryPause)
	}
	return nil, errors.New("this is impossible")
}
