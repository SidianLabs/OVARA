package main

import (
	"flag"
	"fmt"
	"os"

	"ovara.tools.migration/internal/converter"
	"ovara.tools.migration/internal/exporter"
	"ovara.tools.migration/internal/importer"
	"ovara.tools.migration/internal/validator"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "import":
		cmdImport(args)
	case "export":
		cmdExport(args)
	case "config":
		cmdConfig(args)
	case "validate":
		cmdValidate(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: ovara migrate <command> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  import    Import local data to control plane")
	fmt.Fprintln(os.Stderr, "  export    Export data from control plane to local")
	fmt.Fprintln(os.Stderr, "  config    Convert legacy config to v1 format")
	fmt.Fprintln(os.Stderr, "  validate  Validate data files")
}

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	source := fs.String("source", "", "source directory containing JSONL files")
	target := fs.String("target", "", "target API endpoint URL")
	apiKey := fs.String("api-key", "", "API key for authentication")
	dryRun := fs.Bool("dry-run", false, "perform a dry run without making changes")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ovara migrate import [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *source == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "error: --source and --target are required")
		fs.Usage()
		os.Exit(1)
	}

	imp := importer.New(*source, *target, *apiKey, *dryRun)
	result, err := imp.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "import failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nImport complete:\n")
	fmt.Printf("  Files processed: %d\n", result.FilesProcessed)
	fmt.Printf("  Records imported: %d\n", result.RecordsImported)
	fmt.Printf("  Errors: %d\n", result.Errors)
}

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	source := fs.String("source", "", "source API endpoint URL")
	target := fs.String("target", "", "target directory for exported files")
	apiKey := fs.String("api-key", "", "API key for authentication")
	dryRun := fs.Bool("dry-run", false, "perform a dry run without making changes")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ovara migrate export [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *source == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "error: --source and --target are required")
		fs.Usage()
		os.Exit(1)
	}

	exp := exporter.New(*source, *target, *apiKey, *dryRun)
	result, err := exp.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "export failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nExport complete:\n")
	fmt.Printf("  Files written: %d\n", result.FilesWritten)
	fmt.Printf("  Records exported: %d\n", result.RecordsExported)
	fmt.Printf("  Errors: %d\n", result.Errors)
}

func cmdConfig(args []string) {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	from := fs.String("from", "", "input legacy config file path")
	to := fs.String("to", "", "output v1 config file path")
	dryRun := fs.Bool("dry-run", false, "perform a dry run without making changes")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ovara migrate config [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "error: --from and --to are required")
		fs.Usage()
		os.Exit(1)
	}

	conv := converter.New(*dryRun)
	if err := conv.ConvertLegacyToV1(*from, *to); err != nil {
		fmt.Fprintf(os.Stderr, "config conversion failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Config conversion complete")
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("path", "", "file or directory to validate")
	dryRun := fs.Bool("dry-run", false, "perform a dry run")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ovara migrate validate [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "error: --path is required")
		fs.Usage()
		os.Exit(1)
	}

	v := validator.New(*dryRun)

	var result *validator.ValidationResult
	var err error

	info, err := os.Stat(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if info.IsDir() {
		result, err = v.ValidateDirectory(*path)
	} else if *path != "" && len(*path) >= 6 && (*path)[len(*path)-6:] == ".jsonl" {
		result, err = v.ValidateJSONLFile(*path)
	} else {
		result, err = v.ValidateConfig(*path)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "validation failed: %v\n", err)
		os.Exit(1)
	}

	if result.Valid {
		fmt.Println("Validation passed")
	} else {
		fmt.Println("Validation failed")
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	if !result.Valid {
		os.Exit(1)
	}
}
