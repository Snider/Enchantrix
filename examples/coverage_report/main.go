package main

import (
	"fmt"
)

func main() {
	fmt.Println("--- Test Coverage Demo ---")
	fmt.Println("")
	fmt.Println("This example demonstrates how to generate and interpret a test coverage report.")
	fmt.Println("")
	fmt.Println("1. Generate a coverage profile:")
	fmt.Println("   go test ./... -coverprofile=coverage.out")
	fmt.Println("")
	fmt.Println("2. View the coverage report in your browser:")
	fmt.Println("   go tool cover -html=coverage.out")
	fmt.Println("")
	fmt.Println("3. View the coverage report in your terminal:")
	fmt.Println("   go tool cover -func=coverage.out")
	fmt.Println("")
}
