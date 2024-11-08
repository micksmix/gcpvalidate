package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"

	"golang.org/x/oauth2/google"
	"golang.org/x/sync/semaphore"
)

const (
	maxConcurrentValidations = 500
)

type ValidationResult struct {
	Path     string
	Metadata []string
}

type GcpValidator struct {
	regex     *regexp.Regexp
	semaphore *semaphore.Weighted
}

func NewGcpValidator() (*GcpValidator, error) {
	regex, err := regexp.Compile(`(?m)(?mis)(\{[^{}]*"auth_provider_x509_cert_url":.{0,512}?})|\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*"auth_provider_x509_cert_url":\s*".+?"(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %v", err)
	}
	return &GcpValidator{
		regex:     regex,
		semaphore: semaphore.NewWeighted(maxConcurrentValidations),
	}, nil
}

func (v *GcpValidator) ValidateGcpCredentials(ctx context.Context, gcpJSON []byte) (bool, []string, error) {
	if err := v.semaphore.Acquire(ctx, 1); err != nil {
		return false, nil, err
	}
	defer v.semaphore.Release(1)

	var tokenInfo map[string]interface{}
	if err := json.Unmarshal(gcpJSON, &tokenInfo); err != nil {
		return false, nil, err
	}

	projectID := tokenInfo["project_id"]
	clientEmail := tokenInfo["client_email"]
	credentialType := tokenInfo["type"]

	if projectID == nil || clientEmail == nil || credentialType == nil {
		return false, nil, nil
	}

	saKey, err := google.JWTConfigFromJSON(gcpJSON)
	if err != nil {
		return false, nil, fmt.Errorf("failed to parse service account key: %v", err)
	}

	_, err = saKey.TokenSource(ctx).Token()
	if err != nil {
		return false, nil, fmt.Errorf("failed to validate GCP credentials: %v", err)
	}

	metadata := []string{
		fmt.Sprintf("GCP Credential Type == %v", credentialType),
		fmt.Sprintf("GCP Project ID == %v", projectID),
		fmt.Sprintf("GCP Client Email == %v", clientEmail),
	}
	return true, metadata, nil
}

func (v *GcpValidator) ExtractCredentials(content []byte) [][]byte {
	matches := v.regex.FindAll(content, -1)
	var credentials [][]byte
	for _, match := range matches {
		credentials = append(credentials, match)
	}
	return credentials
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <directory_to_scan>", os.Args[0])
	}

	dir := os.Args[1]
	validator, err := NewGcpValidator()
	if err != nil {
		log.Fatalf("Failed to create GCP validator: %v", err)
	}

	var wg sync.WaitGroup
	ctx := context.Background()
	results := make(chan ValidationResult)
	go func() {
		for result := range results {
			fmt.Printf("\nValid credentials found in %s:\n", result.Path)
			for _, item := range result.Metadata {
				fmt.Println(item)
			}
		}
		fmt.Println("Scan complete!")
	}()

	fileCount := int64(0)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		atomic.AddInt64(&fileCount, 1)
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			content, err := ioutil.ReadFile(path)
			if err != nil {
				log.Printf("Failed to read file %s: %v", path, err)
				return
			}

			credentials := validator.ExtractCredentials(content)
			for _, credential := range credentials {
				valid, metadata, err := validator.ValidateGcpCredentials(ctx, credential)
				if err != nil {
					log.Printf("Validation error: %v", err)
					continue
				}
				if valid {
					results <- ValidationResult{Path: path, Metadata: metadata}
				}
			}
		}(path)
		return nil
	})

	if err != nil {
		log.Fatalf("Failed to walk directory: %v", err)
	}
	wg.Wait()
	close(results)
}
