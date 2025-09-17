package server

import (
	"encoding/json"

	"github.com/BlockPILabs/aggregator/config"
	"github.com/BlockPILabs/aggregator/loadbalance"
	"github.com/valyala/fasthttp"
)

var BasicAuthPrefix = []byte("Basic ")

func RootHandler(ctx *fasthttp.RequestCtx) {
	ctx.WriteString("hello!")
}

func StatusHandler(ctx *fasthttp.RequestCtx) {
	st := map[string]any{}
	st["mrt"] = config.Default().Mrt
	data, _ := json.Marshal(st)
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Write(data)
}

func RouteConfigHandler(ctx *fasthttp.RequestCtx) {
	data, _ := json.Marshal(config.Default())
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Write(data)
}

func RouteUpdateConfigHandler(ctx *fasthttp.RequestCtx) {
	cfg := config.Config{}
	err := json.Unmarshal(ctx.Request.Body(), &cfg)
	if err != nil {
		ctx.Error("error parse config", fasthttp.StatusInternalServerError)
		return
	}

	defaultCfg := config.Default()
	cfg.Mrt = defaultCfg.Mrt

	dbs := defaultCfg.AuthorityDB
	for i := 0; i < len(dbs); i++ {
		for _, adb2 := range cfg.AuthorityDB {
			if dbs[i].Name == adb2.Name {
				dbs[i].Enable = adb2.Enable
			}
		}
	}

	cfg.AuthorityDB = dbs

	config.SetDefault(&cfg)
	loadbalance.LoadFromConfig()

	config.Save()

	data, _ := json.Marshal(cfg)
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Write(data)
}

func RouteRestoreConfigHandler(ctx *fasthttp.RequestCtx) {
	config.LoadDefault()

}
