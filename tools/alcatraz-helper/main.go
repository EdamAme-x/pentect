package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/hoophq/alcatraz"
)

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
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			os.Exit(2)
		}
		results := engine.Analyze(req.Text, alcatraz.Options{})
		findings := make([]finding, 0, len(results))
		for _, result := range results {
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
