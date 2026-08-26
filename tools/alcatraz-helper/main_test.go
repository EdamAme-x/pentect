package main

import (
	"testing"

	"github.com/hoophq/alcatraz"
)

func TestDefaultPIIEntities(t *testing.T) {
	engine := alcatraz.NewEngine()
	const threshold = 0.4
	tests := []struct {
		name   string
		text   string
		entity string
	}{
		{"email", "email alice@example.com", "EMAIL_ADDRESS"},
		{"phone", "phone +1 415-555-2671", "PHONE_NUMBER"},
		{"card", "card 4111 1111 1111 1111", "CREDIT_CARD"},
		{"iban", "IBAN DE89 3704 0044 0532 0130 00", "IBAN_CODE"},
		{"uk nino", "NINO AB 12 34 56 C", "UK_NINO"},
		{"india pan", "PAN ABCDE1234F", "IN_PAN"},
		{"italy fiscal code", "codice fiscale RSSMRA85T10A562C", "IT_FISCAL_CODE"},
		{"spain nif", "NIF 12345678Z", "ES_NIF"},
		{"spain nie", "NIE X1234567L", "ES_NIE"},
		{"singapore fin", "FIN F1234567N", "SG_FIN"},
		{"korea rrn", "RRN 900101-1234568", "KR_RRN"},
		{"finland identity code", "HETU 131052-308T", "FI_PERSONAL_IDENTITY_CODE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := analyze(engine, tt.text, threshold)
			for _, result := range results {
				if result.EntityType == tt.entity {
					return
				}
			}
			t.Fatalf("%s was not detected in %#v", tt.entity, results)
		})
	}
}

func TestDefaultPIIEntitiesPreserveDeveloperData(t *testing.T) {
	engine := alcatraz.NewEngine()
	const threshold = 0.4
	texts := []string{
		"request id 550e8400-e29b-41d4-a716-446655440000",
		"released version 10.20.30 at 2026-08-26T12:34:56Z",
		"listen on http://localhost:8080 and 127.0.0.1",
		"docs https://platform.openai.com/docs/api-reference/responses",
		"fixture order=123456789 account=987654321",
		"const AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE",
	}
	for _, text := range texts {
		if results := analyze(engine, text, threshold); len(results) != 0 {
			t.Errorf("developer data %q produced PII findings: %#v", text, results)
		}
	}
}

func BenchmarkDefaultPIIEntities(b *testing.B) {
	engine := alcatraz.NewEngine()
	const threshold = 0.4
	text := "email alice@example.com, IBAN DE89 3704 0044 0532 0130 00, NINO AB 12 34 56 C"
	b.ResetTimer()
	for range b.N {
		_ = analyze(engine, text, threshold)
	}
}
