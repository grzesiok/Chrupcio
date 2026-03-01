package main

import (
	"os"
	"time"

	"github.com/kardianos/service"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	for {
		// Main service loop
		logger.Infow("Service running...")
		time.Sleep(10 * time.Second)
	}
}

func (p *program) Stop(s service.Service) error {
	logger.Infow("Service stopping...")
	return nil
}

func main() {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()
	logger = zapLogger.Sugar()

	svcConfig := &service.Config{
		Name:        "Chrupcio",
		DisplayName: "Chrupcio Cross-Platform Service",
		Description: "A cross-platform Go service/daemon skeleton.",
	}
	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Errorw("Cannot create service", "error", err)
		os.Exit(1)
	}
	err = s.Run()
	if err != nil {
		logger.Errorw("Service failed", "error", err)
		os.Exit(1)
	}
}
