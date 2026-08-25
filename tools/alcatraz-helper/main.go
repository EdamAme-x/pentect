package main

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"

	"github.com/hoophq/alcatraz"
	"github.com/hoophq/alcatraz/entities"
)

var uuidPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

var piiEntities = []string{
	entities.EmailAddress,
	entities.PhoneNumber,
	entities.CreditCard,
}

type request struct {
	ID   uint64 `json:"id"`
	Text string `json:"text"`
}

type finding struct {
	Entity string  `json:"entity"`
	Start  int     `json:"start"`
	End    int     `json:"end"`
	Score  float64 `json:"score"`
}

type response struct {
	ID       uint64    `json:"id"`
	Findings []finding `json:"findings"`
}

func main() {
	engine := alcatraz.NewEngine()
	threshold := 0.4
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			os.Exit(2)
		}
		results := engine.Analyze(req.Text, alcatraz.Options{
			Entities:  piiEntities,
			Threshold: &threshold,
		})
		uuidRanges := uuidPattern.FindAllStringIndex(req.Text, -1)
		findings := make([]finding, 0, len(results))
		for _, result := range results {
			if containedInAny(result.Start, result.End, uuidRanges) {
				continue
			}
			findings = append(findings, finding{
				Entity: result.EntityType,
				Start:  result.Start,
				End:    result.End,
				Score:  result.Score,
			})
		}
		if err := encoder.Encode(response{ID: req.ID, Findings: findings}); err != nil {
			os.Exit(2)
		}
	}
	if scanner.Err() != nil {
		os.Exit(2)
	}
}

func containedInAny(start, end int, ranges [][]int) bool {
	for _, span := range ranges {
		if span[0] <= start && end <= span[1] {
			return true
		}
	}
	return false
}
