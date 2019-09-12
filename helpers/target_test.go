package helpers

import (
	"reflect"
	"testing"
)

func TestTarget_IsHostname(t *testing.T) {
	var f bool
	type fields struct {
		Value      string
		hostname   *bool
		domainName *bool
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "ValidHostname",
			fields: fields{
				Value: "localhost",
			},
			want: true,
		},
		{
			name: "IsAnIP",
			fields: fields{
				Value: "127.0.0.1",
			},
			want: false,
		},
		{
			name: "DoesNotResolve",
			fields: fields{
				Value: "notAHostname",
			},
			want: false,
		},
		{
			name: "ReturnsCachedValue",
			fields: fields{
				Value:    "",
				hostname: &f,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := Target{
				Value:      tt.fields.Value,
				hostname:   tt.fields.hostname,
				domainName: tt.fields.domainName,
			}
			got, err := target.IsHostname()
			if (err != nil) != tt.wantErr {
				t.Errorf("Target.IsHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Target.IsHostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasSOARecord(t *testing.T) {
	type hasSOARecordTest struct {
		Name    string
		Domain  string
		want    bool
		wantErr bool
	}
	tests := []hasSOARecordTest{
		{
			Name:   "Detects a SOA domain",
			Domain: "example.com",
			want:   true,
		},
		{
			Name:   "Detects not a SOA domain",
			Domain: "www.example.com",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			got, err := hasSOARecord(tt.Domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Got error %s != tt.wantError %v", err.Error(), tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTarget_IsDomainName(t *testing.T) {
	var f bool
	type fields struct {
		Value      string
		hostname   *bool
		domainName *bool
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "ValidDomainName",
			fields: fields{
				Value: "example.com",
			},
			want: true,
		},
		{
			name: "NotValidDomainName",
			fields: fields{
				Value: "www.example.com",
			},
			want: false,
		},
		{
			name: "IsAnIP",
			fields: fields{
				Value: "127.0.0.1",
			},
			want: false,
		},
		{
			name: "DoesNotResolve",
			fields: fields{
				Value: "notAHostname",
			},
			want: false,
		},
		{
			name: "ReturnsCachedValue",
			fields: fields{
				Value:      "",
				domainName: &f,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := Target{
				Value:      tt.fields.Value,
				hostname:   tt.fields.hostname,
				domainName: tt.fields.domainName,
			}
			got, err := target.IsDomainName()
			if (err != nil) != tt.wantErr {
				t.Errorf("Target.IsDomainName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Target.IsDomainName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTarget_IsIP(t *testing.T) {
	type fields struct {
		Value string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "ValidIP",
			fields: fields{
				Value: "127.0.0.1",
			},
			want: true,
		},
		{
			name: "ValidCIDR",
			fields: fields{
				Value: "127.0.0.1/24",
			},
			want: false,
		},
		{
			name: "ValidDomainName",
			fields: fields{
				Value: "example.com",
			},
			want: false,
		},
		{
			name: "ValidHostname",
			fields: fields{
				Value: "www.example.com",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := Target{
				Value: tt.fields.Value,
			}
			got := target.IsIP()
			if got != tt.want {
				t.Errorf("Target.IsIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTarget_IsCIDR(t *testing.T) {
	type fields struct {
		Value string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "ValidCIDR",
			fields: fields{
				Value: "127.0.0.1/24",
			},
			want: true,
		},
		{
			name: "ValidIP",
			fields: fields{
				Value: "127.0.0.1",
			},
			want: false,
		},
		{
			name: "ValidDomainName",
			fields: fields{
				Value: "example.com",
			},
			want: false,
		},
		{
			name: "ValidHostname",
			fields: fields{
				Value: "www.example.com",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := Target{
				Value: tt.fields.Value,
			}
			got := target.IsCIDR()
			if got != tt.want {
				t.Errorf("Target.IsCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTarget_IsScannable(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "ValidCIDR",
			target: "1.1.1.1/24",
			want:   true,
		},
		{
			name:   "ValidIP",
			target: "1.1.1.1",
			want:   true,
		},
		{
			name:   "ValidHostname",
			target: "www.example.com",
			want:   true,
		},
		{
			name:   "ValidURL",
			target: "http://www.example.com",
			want:   true,
		},
		{
			name:   "ValidDomainName",
			target: "example.com",
			want:   true,
		},
		{
			name:   "ValidDockerImage",
			target: "registry.hub.docker.com/library/alpine:latest",
			want:   true,
		},
		{
			name:   "ValidAWSAccount",
			target: "arn:aws:iam::111111111111:root",
			want:   true,
		},
		{
			name:   "HostnameNotResolve",
			target: "test.example.com",
			want:   true,
		},
		{
			name:   "PrivateCIDR",
			target: "127.0.0.1/24",
			want:   false,
		},
		{
			name:   "PrivateIP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "HostnameResolvesPrivate",
			target: "localhost",
			want:   false,
		},
		{
			name:   "URLResolvesPrivate",
			target: "https://localhost",
			want:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsScannable(tt.target)
			if got != tt.want {
				t.Errorf("Target.IsScannable() = %v, want %v", got, tt.want)
			}
		})
	}
}
