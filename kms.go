package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	//"reflect"
)

type KMSBuilder struct{}

func (builder KMSBuilder) Name() string {
	return "KMS"
}

func (builder KMSBuilder) Populate(session *session.Session, tree *AWSTree) {
	svc := kms.New(session)

	// Listing all CMK keys
	params := &kms.ListKeysInput{}
	keys, err := svc.ListKeys(params)
	if err != nil {
		log.Fatalf("Couldn't list CMKs: %v\n", err)
	}

	kmsData := KMSData{Keys: make([]KMSKey, 0, len(keys.Keys))}

	for _, key := range keys.Keys {
		kmsData.Keys = append(kmsData.Keys, *buildKey(svc, key))
	}

	tree.Audit.KMS = &kmsData
}

func buildKey(svc *kms.KMS, key *kms.KeyListEntry) *KMSKey {
	k := &KMSKey{}
	k.ARN = *key.KeyArn
	k.ID = *key.KeyId

	// CMK description
	keyDescription := describeCMK(svc, key)
	if keyDescription != nil {
		k.Enabled = *keyDescription.KeyMetadata.Enabled
		k.State = *keyDescription.KeyMetadata.KeyState
	}

	// CMK rotation
	keyRotation := getCMKRotateStatus(svc, key)
	if keyRotation != nil {
		k.Rotation = *keyRotation.KeyRotationEnabled
	}

	// CMK policy
	//------------
	// Retrieve CMK policy
	keyPolicy := getAllKeyPolicy(svc, key)

	if keyPolicy != nil {
		// Create policyData struct with statement array
		policyData := &KMSPolicy{Statement: make([]PolicyStatement, 0, len(keyPolicy.PolicyNames))}

		// CMK contains one policy
		policyData.Name = *keyPolicy.PolicyNames[0]

		// Retrieve CMK policy content
		policyContent := getKeyPolicyContent(svc, key, policyData.Name)

		// *** Policy content is a long string in json format. Hence requires to self formart it to get data needed
		// Split the string via \n
		arr := strings.Split(*policyContent.Policy, "\n")

		// Initialize an empty PolicyStatement struct
		var statement *PolicyStatement = &PolicyStatement{}

		// Initialize sIndex variable for keeping track which statement it is currently at
		sIndex := -1

		// Loop through every values
		for _, w := range arr {
			// Remove left and right spaces
			str := strings.TrimSpace(w)

			// If the value contains keyword 'Sid'
			if strings.Contains(str, "Sid") {

				// Create new PolicyStatement stuct
				statement = &PolicyStatement{}

				// Format the string to get only Sid value
				sidReplacer := strings.NewReplacer("Sid", "", "\"", "", ",", "", ":", "", " ", "")
				sid := sidReplacer.Replace(str)
				statement.Sid = sid

				// Update PolicyStatement struct and append into policyData statement array
				policyData.Statement = append(policyData.Statement, *statement)

				// Update statement index location
				sIndex++
			}

			// If the value contains keyword 'BypassPolicyLockoutSafetyCheck'
			if strings.Contains(str, "BypassPolicyLockoutSafetyCheck") {

				// Format the string to get only BypassPolicyLockoutSafetyCheck value
				bplscReplacer := strings.NewReplacer("kms:BypassPolicyLockoutSafetyCheck", "", "\"", "", ":", "", " ", "")
				bplsc := bplscReplacer.Replace(str)

				// Update policyData statement BypassPolicyLockoutSafetyCheck value using statement index
				if bplsc == "true" {
					policyData.Statement[sIndex].BypassPolicyLockoutSafetyCheck = true
				} else {
					policyData.Statement[sIndex].BypassPolicyLockoutSafetyCheck = false
				}
			}

			// If the value contains keyword 'Action'
			if strings.Contains(str, "Action") {

				// Format the string into an array
				actionReplacer := strings.NewReplacer("\"", "", "[", "", ":", "", "Action", "", "]", "", " ", "")
				actions := actionReplacer.Replace(str)
				actionsArr := strings.Split(actions, ",")

				// Update policyData statement Action value using statement index
				policyData.Statement[sIndex].Action = actionsArr[:len(actionsArr)-1]
			}

		}

		fmt.Println("...")

		k.Policy = *policyData

	}

	return k
}

//
// Querying for CMK descriptions
//
func describeCMK(svc *kms.KMS, key *kms.KeyListEntry) *kms.DescribeKeyOutput {
	params := &kms.DescribeKeyInput{
		KeyId: aws.String(*key.KeyId), // Required
	}
	resp, err := svc.DescribeKey(params)

	if err != nil {
		// Log the error
		log.Fatalf("Couldn't get CMK description: %v\n", err)
		return nil
	}

	// return response data.
	return resp
}

//
// Querying for CMK rotation status
//
func getCMKRotateStatus(svc *kms.KMS, key *kms.KeyListEntry) *kms.GetKeyRotationStatusOutput {
	params := &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(*key.KeyId), // Required
	}
	resp, err := svc.GetKeyRotationStatus(params)

	if err != nil {
		// Log the error
		log.Fatalf("Couldn't get CMK rotation status: %v\n", err)
		return nil
	}

	// return response data.
	return resp
}

//
// Querying for all policies of a CMK
//
func getAllKeyPolicy(svc *kms.KMS, key *kms.KeyListEntry) *kms.ListKeyPoliciesOutput {
	params := &kms.ListKeyPoliciesInput{
		KeyId: aws.String(*key.KeyId), // Required
	}
	keyPolicies, err := svc.ListKeyPolicies(params)

	if err != nil {
		// Log the error
		log.Fatalf("Couldn't get CMK policies: %v\n", err)
		return nil
	}

	return keyPolicies
}

//
// Querying for CMK policy content
//
func getKeyPolicyContent(svc *kms.KMS, key *kms.KeyListEntry, policyName string) *kms.GetKeyPolicyOutput {
	content_params := &kms.GetKeyPolicyInput{
		KeyId:      aws.String(*key.KeyId), // Required
		PolicyName: aws.String(policyName), // Required
	}

	policyContent, err := svc.GetKeyPolicy(content_params)

	if err != nil {
		// Log the error
		log.Fatalf("Couldn't get CMK policy: %v\n", err)
		return nil
	}

	return policyContent
}

// KMSData contains all KMS related data collected through the AWS key scan.
type KMSData struct {
	Keys []KMSKey `json:"keys"`
}

// KMSKey represents a single KMS CMK, as collected through an AWS key scan.
type KMSKey struct {
	ARN      string    `json:"arn"`
	ID       string    `json:"id"`
	Enabled  bool      `json:"enabled"`
	State    string    `json:"state"`
	Rotation bool      `json:"rotation"`
	Policy   KMSPolicy `json:"policy"`
}

// KMSPolicy contains all KMS related policy data collected from CMK.
type KMSPolicy struct {
	Name      string            `json:name`
	Statement []PolicyStatement `json:statement`
}

// PolicyStatement represents a single KMS CMK policy statement.
type PolicyStatement struct {
	Sid                            string   `json:"sid"`
	Action                         []string `json:"action"`
	BypassPolicyLockoutSafetyCheck bool     `json:"BypassPolicyLockoutSafetyCheck"`
}
