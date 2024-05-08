package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/sirupsen/logrus"
)

type CustomWriter struct {
	logger logrus.FieldLogger
}

type internalWriter struct {
	ctx          *context.Context
	sourceLogger string
	logger       logrus.FieldLogger
}

func newInternalWriter(ctx context.Context, logger logrus.FieldLogger, sourceLogger string) *internalWriter {
	return &internalWriter{
		ctx:          &ctx,
		sourceLogger: sourceLogger,
		logger:       logger,
	}
}

func NewCustomWriter(logger logrus.FieldLogger) *CustomWriter {
	return &CustomWriter{
		logger: logger,
	}
}

func (c CustomWriter) GetWriter(ctx context.Context, sourceLogger string) writer.Writer {
	return newInternalWriter(ctx, c.logger, sourceLogger)
}

func (i internalWriter) Write(data []byte, level levels.Level) {
	var resultMap map[string]interface{}
	if err := json.Unmarshal(data, &resultMap); err != nil {
		i.logger.Error(fmt.Sprintf("Error unmarshalling log data from %s: %s", i.sourceLogger, err))
		return
	}

	// Extract msg from map
	msgField := resultMap["msg"].(string)

	// Remove extracted fields from map
	delete(resultMap, "msg")

	// Get the string representation of the log level
	levelString := level.String()

	// Write to our logger
	i.writeToLogger(levelString, msgField, resultMap)
}

func (i internalWriter) writeToLogger(level string, msg string, additionalData map[string]interface{}) {

	combinedMsg := fmt.Sprintf("[%s] : %s", i.sourceLogger, msg)

	var args []interface{}
	// args = append(args, combinedMsg)
	for key, value := range additionalData {
		args = append(args, key)
		args = append(args, value)
	}

	switch level {
	case "fatal":
		i.logger.Fatal(combinedMsg, args)
	case "silent":
		i.logger.Info(combinedMsg, args)
	case "error":
		i.logger.Error(combinedMsg, args)
	case "info":
		i.logger.Info(combinedMsg, args)
	case "warning":
		i.logger.Warning(combinedMsg, args)
	case "debug":
		i.logger.Debug(combinedMsg, args)
	case "verbose":
		i.logger.Debug(combinedMsg, args)
	default:
		i.logger.Warning(fmt.Sprintf("[Unknown log level] %s", combinedMsg))
	}
}
