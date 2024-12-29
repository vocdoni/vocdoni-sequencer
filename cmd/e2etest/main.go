package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

const nVoters = 3

const (
	// Define file paths
	step1pkFile = "step1pk.json"
	step1vkFile = "step1vk.json"

	step1resultsFile = "step1results.json"
	step1witnessFile = "step1witness.json"
)

func main() {
	start := time.Now()
	CompileStep1()
	fmt.Println("compiling step1:", time.Since(start))

	start = time.Now()
	ProveStep1()
	fmt.Println("prove step1:", time.Since(start))
}

func writeToFile(filename string, data any) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		return err
	}

	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func CompileStep1() {
	if !fileExists(step1pkFile) || !fileExists(step1vkFile) {
		_, vk, err := voteverifier.CompileAndSetup()
		if err != nil {
			return
		}
		// if err := writeToFile(step1pkFile, pk); err != nil {
		// 	return
		// }
		if err := writeToFile(step1vkFile, vk); err != nil {
			return
		}
	}
}

func ProveStep1() {
	if !fileExists(step1resultsFile) || !fileExists(step1witnessFile) {
		results, witness, err := voteverifier.GenProofsForTest(nil, nVoters)
		if err != nil {
			return
		}
		if err := writeToFile(step1resultsFile, results); err != nil {
			return
		}
		if err := writeToFile(step1witnessFile, witness); err != nil {
			return
		}
	}
}
