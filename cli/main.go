package main

import (
	"fmt"
	"os"
	"strings"

	"cybermind-cli/api"
)

func main() {
	fmt.Println("⚡ CyberMind CLI Initialized")

	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Println("Usage: cybermind chat \"<your prompt>\"")
		return
	}

	command := args[0]

	switch command {
	case "chat":
		if len(args) < 2 {
			fmt.Println("Usage: cybermind chat \"<your prompt>\"")
			return
		}
		prompt := strings.Join(args[1:], " ")
		response, err := api.SendPrompt(prompt)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println("Response:", response)
	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}
