package config

import (
	"errors"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/kr/pretty"

	"github.com/manelmontilla/vulcan-check-sdk/internal/push/rest"
)

type overrideTest struct {
	name   string
	params overrideTestParams
	want   *Config
}

type overrideTestParams struct {
	testFile string
	envVars  map[string]string
}

func TestOverrideConfigFromEnvVars(t *testing.T) {
	tests := []overrideTest{
		{
			name: "TestOverrideAllParams",
			params: overrideTestParams{
				envVars: map[string]string{
					loggerLevelEnv:      "level",
					loggerFormatterEnv:  "fmt",
					checkTargetEnv:      "target",
					checkOptionsEnv:     "opts",
					checkIDEnv:          "id",
					commModeEnv:         "push",
					pushAgentAddr:       "endpoint",
					checkTypeNameEnv:    "acheck",
					checkTypeVersionEnv: "1",
					pushMsgBufferLen:    strconv.Itoa(11),
				},
				testFile: "testdata/OverrideTestConfig.toml",
			},
			want: &Config{
				Check: CheckConfig{
					Target:           "target",
					Opts:             "opts",
					CheckID:          "id",
					CheckTypeName:    "acheck",
					CheckTypeVersion: "1",
				},
				CommMode: "push",
				Push: rest.RestPusherConfig{
					AgentAddr: "endpoint",
					BufferLen: 11,
				},
				Log: LogConfig{
					LogFmt:   "fmt",
					LogLevel: "level",
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := setEnvVars(tt.params.envVars)
			if err != nil {
				t.Error(err)
			}
			got, err := LoadConfigFromFile(tt.params.testFile)
			if err != nil {
				t.Error(err)
			}
			if got == nil {
				t.Error(errors.New("Error returned config was null"))
			}
			OverrideConfigFromEnvVars(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Error in test %s. \nWant: %s Got: %s.\n diffs %+v", tt.name, pretty.Sprint(tt.want), pretty.Sprint(got), pretty.Diff(tt.want, got))
			}

		})
	}
}

func TestOverrideConfigFromOpts(t *testing.T) {
	tests := []overrideTest{
		{
			name: "TestOverrideAllParams",
			params: overrideTestParams{
				envVars: map[string]string{
					loggerLevelEnv:      "level",
					loggerFormatterEnv:  "fmt",
					checkTargetEnv:      "target",
					checkOptionsEnv:     "{\"debug\":true}",
					checkIDEnv:          "id",
					commModeEnv:         "push",
					pushAgentAddr:       "endpoint",
					checkTypeNameEnv:    "acheck",
					checkTypeVersionEnv: "1",
					pushMsgBufferLen:    strconv.Itoa(11),
				},
				testFile: "testdata/OverrideTestConfig.toml",
			},
			want: &Config{
				Check: CheckConfig{
					Target:           "target",
					Opts:             "{\"debug\":true}",
					CheckID:          "id",
					CheckTypeName:    "acheck",
					CheckTypeVersion: "1",
				},
				CommMode: "push",
				Push: rest.RestPusherConfig{
					AgentAddr: "endpoint",
					BufferLen: 11,
				},
				Log: LogConfig{
					LogFmt:   "fmt",
					LogLevel: "debug",
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := setEnvVars(tt.params.envVars)
			if err != nil {
				t.Error(err)
			}

			got, err := LoadConfigFromFile(tt.params.testFile)
			if err != nil {
				t.Error(err)
			}
			if got == nil {
				t.Error(errors.New("Error returned config was null"))
			}
			OverrideConfigFromEnvVars(got)
			OverrideConfigFromOptions(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Error in test %s. \nWant: %s Got: %s.\n diffs %+v", tt.name, pretty.Sprint(tt.want), pretty.Sprint(got), pretty.Diff(tt.want, got))
			}

		})
	}
}

func setEnvVars(envVars map[string]string) error {
	for k, v := range envVars {
		err := os.Setenv(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}
