package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/continuous-security/aws-audit/tree"
)

func main() {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1")},
	)
	if err != nil {
		log.Fatalf("Couldn't set up session: %v\n", err)
	}

	iamData, err := tree.BuildIAM(sess)
	if err != nil {
		log.Fatalf("Couldn't build IAM data: %v\n", err)
	}

	// tree.BuildIAM(&audit, users, keys)
	bytes, err := json.MarshalIndent(iamData, "", "  ")
	fmt.Printf("\n%v\n", string(bytes))
}
