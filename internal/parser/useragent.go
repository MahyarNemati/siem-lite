package parser

import "strings"

// DeviceFromUserAgent reduces a User-Agent to a coarse "os/client" label.
// It is deliberately cheap: the detection engine only needs a stable key
// to notice when an account shows up from something it has not used before.
func DeviceFromUserAgent(ua string) string {
	if ua == "" || ua == "-" {
		return ""
	}
	l := strings.ToLower(ua)
	osName := "other"
	switch {
	case strings.Contains(l, "android"):
		osName = "android"
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"):
		osName = "ios"
	case strings.Contains(l, "windows"):
		osName = "windows"
	case strings.Contains(l, "mac os x"), strings.Contains(l, "macintosh"):
		osName = "macos"
	case strings.Contains(l, "linux"):
		osName = "linux"
	}
	client := "other"
	switch {
	case strings.Contains(l, "curl/"):
		client = "curl"
	case strings.Contains(l, "python-requests"), strings.Contains(l, "python-urllib"):
		client = "python"
	case strings.Contains(l, "go-http-client"):
		client = "go"
	case strings.Contains(l, "edg/"):
		client = "edge"
	case strings.Contains(l, "firefox/"):
		client = "firefox"
	case strings.Contains(l, "chrome/"):
		client = "chrome"
	case strings.Contains(l, "safari/"):
		client = "safari"
	case strings.Contains(l, "bot"), strings.Contains(l, "spider"), strings.Contains(l, "crawl"):
		client = "bot"
	}
	return osName + "/" + client
}
