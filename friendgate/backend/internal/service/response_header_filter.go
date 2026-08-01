package service

import (
	"github.com/HCRXchenghong/api-codex/internal/config"
	"github.com/HCRXchenghong/api-codex/internal/util/responseheaders"
)

func compileResponseHeaderFilter(cfg *config.Config) *responseheaders.CompiledHeaderFilter {
	if cfg == nil {
		return nil
	}
	return responseheaders.CompileHeaderFilter(cfg.Security.ResponseHeaders)
}
