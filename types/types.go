package types

import (
	"github.com/pkg/browser"
	"github.com/rs/zerolog/log"
)

type FilePath string

type OpenBrowserFunc func(url string)

var (
	DefaultOpenBrowserFunc OpenBrowserFunc = func(url string) {
		browser.Stdout = log.Logger
		_ = browser.OpenURL(url)
	}
)
