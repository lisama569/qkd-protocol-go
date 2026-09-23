package qkd

import (
	"errors"
	"testing"
)

func TestValidationRejects(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		field string
	}{
		{"missing photons", Config{}, "NumPhotons"},
		{"bad efficiency", Config{NumPhotons: 10, DetectorEfficiency: 2}, "DetectorEfficiency"},
		{"dark >= 1", Config{NumPhotons: 10, DetectorEfficiency: 0.9, DarkCountProb: 1}, "DarkCountProb"},
		{"sample >= 1", Config{NumPhotons: 10, DetectorEfficiency: 0.9, DarkCountProb: 0.001, SampleFraction: 1}, "SampleFraction"},
		{"dark dominates signal", Config{NumPhotons: 10, ChannelLossDB: 60, DetectorEfficiency: 0.9, DarkCountProb: 0.5}, "DarkCountProb"},
		{"negative margin", Config{NumPhotons: 10, DetectorEfficiency: 0.9, DarkCountProb: 0.001, SecurityMargin: -1}, "SecurityMargin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("校验输入=%+v, 期望拒绝字段=%s", tc.cfg, tc.field)
			err := tc.cfg.withDefaults().Validate()
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected ValidationError, got %v", err)
			}
			if ve.Field != tc.field {
				t.Fatalf("expected field %q, got %q (%s)", tc.field, ve.Field, ve.Reason)
			}
			t.Logf("拒绝原因: %s", ve.Reason)
		})
	}
}

func TestDefaultsStable(t *testing.T) {
	c := Config{SampleFraction: 0, QBERThreshold: 0, SecurityMargin: 0}
	d := c.withDefaults()
	if d.SampleFraction != DefaultSampleFraction || d.QBERThreshold != DefaultQBERThreshold || d.SecurityMargin != DefaultSecurityMargin {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}
