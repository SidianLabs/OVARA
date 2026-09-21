package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"ovara.tools.benchmarks/internal/generator"
)

func main() {
	target := flag.String("target", "http://localhost:8080", "Gateway URL to benchmark")
	duration := flag.Duration("duration", 30*time.Second, "Duration of the benchmark")
	concurrency := flag.Int("concurrency", 50, "Number of concurrent workers")
	rampUp := flag.Duration("ramp-up", 5*time.Second, "Ramp-up period for adding workers")
	warmup := flag.Duration("warmup", 5*time.Second, "Warmup phase duration")
	output := flag.String("output", "benchmark-report.json", "Output JSON report filename")
	timeSeries := flag.String("timeseries", "timeseries.json", "Output time series filename")
	
	flag.Parse()
	
	fmt.Printf("Ovara Gateway Benchmark Tool\n")
	fmt.Printf("============================\n")
	fmt.Printf("Target: %s\n", *target)
	fmt.Printf("Duration: %v\n", *duration)
	fmt.Printf("Concurrency: %d\n", *concurrency)
	fmt.Printf("Ramp-up: %v\n", *rampUp)
	fmt.Printf("Warmup: %v\n\n", *warmup)
	
	gen := generator.NewLoadGenerator(*target, *concurrency, *duration, *rampUp, *warmup)
	
	report := gen.GenerateLoad()
	
	gen.GetReporter().PrintSummary(report)
	
	if err := gen.GetReporter().WriteJSONReport(report, *output); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing JSON report: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("JSON report written to: %s\n", *output)
	
	if err := gen.GetReporter().WriteTimeSeries(report, *timeSeries); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing time series: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Time series written to: %s\n", *timeSeries)
}