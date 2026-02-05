package main

import (
	auth "Zero-TrustAPIGateWayServer/internal/auth"
	"fmt"
)

func main() {
	fmt.Print("\n=== Test API Key Generator ===\n\n")

	keyString, err := auth.GenerateTestAPIKeySimple()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("📋 Simple Test Key:")
	fmt.Printf("   %s\n\n", keyString)

	apiKey, customKeyString, err := auth.GenerateTestAPIKey("my-custom-key", []string{"admin", "read", "write"})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("🔧 Custom Test Key:")
	fmt.Printf("   ID: %s\n", apiKey.ID)
	fmt.Printf("   Key: %s\n", customKeyString)
	fmt.Printf("   Roles: %v\n\n", apiKey.Roles)

	fmt.Println("💡 Usage:")
	fmt.Printf("   curl -H \"X-API-Key: %s\" http://localhost:8080/api/endpoint\n\n", keyString)
}
