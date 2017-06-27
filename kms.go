package main

import (
	//"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
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

	buildIAMPolicy(session, &kmsData)

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
	buildKeyPolicy(svc, k)

	return k
}

func buildKeyPolicy(svc *kms.KMS, key *KMSKey) {

	// Retrieve CMK policy
	keyPolicy := getAllKeyPolicy(svc, key.ID)

	if keyPolicy != nil {
		// Create policyData struct with statement array
		policyData := &KMSPolicy{Statement: make([]PolicyStatement, 0, len(keyPolicy.PolicyNames))}

		// CMK contains one policy
		policyData.Name = *keyPolicy.PolicyNames[0]

		// Retrieve CMK policy content
		policyContent := getKeyPolicyContent(svc, key.ID, policyData.Name)

		// *** Policy content is a long string in json format. Hence requires to self formart it to get data needed
		// Split the string via \n
		arr := strings.Split(*policyContent.Policy, "\n")

		// Initialize an empty PolicyStatement struct
		var statement *PolicyStatement = &PolicyStatement{}

		// Initialize sIndex variable for keeping track which statement it is currently at
		sIndex := -1
		sid := ""
		// Loop through every values
		for _, w := range arr {
			// Remove left and right spaces
			str := strings.TrimSpace(w)

			// If the value contains keyword 'Sid'
			if strings.Contains(str, "Sid") {
				// Format the string to get only Sid value
				sidReplacer := strings.NewReplacer("Sid", "", "\"", "", ",", "", ":", "", " ", "")
				sid = sidReplacer.Replace(str)
			}

			// If the value contains keyword 'Action'
			if strings.Contains(str, "Action") {

				// Create new PolicyStatement stuct
				statement = &PolicyStatement{}
				statement.Sid = sid

				// Update PolicyStatement struct and append into policyData statement array
				policyData.Statement = append(policyData.Statement, *statement)

				// Update statement index location
				sIndex++
				sid = ""

				// Format the string into an array
				actionReplacer := strings.NewReplacer("\"", "", "[", "", ":", "", "Action", "", "]", "", " ", "")
				actions := actionReplacer.Replace(str)
				actionsArr := strings.Split(actions, ",")

				// Update policyData statement Action value using statement index
				policyData.Statement[sIndex].Action = actionsArr[:len(actionsArr)-1]
			}

			// If the value contains keyword 'BypassPolicyLockoutSafetyCheck'
			if strings.Contains(str, "BypassPolicyLockoutSafetyCheck") {

				// Format the string to get only BypassPolicyLockoutSafetyCheck value
				bplscReplacer := strings.NewReplacer("kms", "", "BypassPolicyLockoutSafetyCheck", "", "\"", "", ":", "", " ", "")
				bplsc := bplscReplacer.Replace(str)

				// Update policyData statement BypassPolicyLockoutSafetyCheck value using statement index
				if bplsc == "true" {
					policyData.Statement[sIndex].BypassPolicyLockoutSafetyCheck = true
				} else {
					policyData.Statement[sIndex].BypassPolicyLockoutSafetyCheck = false
				}
			}

			// If the value contains keyword 'MultiFactorAuthAge'
			if strings.Contains(str, "MultiFactorAuthAge") {

				// Format the string to get only MultiFactorAuthAge value
				mfaReplacer := strings.NewReplacer("MultiFactorAuthAge", "", "aws", "", "\"", "", ",", "", ":", "", " ", "")
				mfa := mfaReplacer.Replace(str)

				// Convert string to int
				mfaInt, mfaerr := strconv.Atoi(mfa)
				if mfaerr != nil {
					// handle error
					log.Fatalf("Couldn't convert mfa to integer: %v\n", mfaerr)
				}
				policyData.Statement[sIndex].MultiFactorAuthAge = mfaInt
			}

		}

		key.Policy = *policyData
	}
}

func buildIAMPolicy(session *session.Session, kmsData *KMSData) {

	//
	//Query for IAM local policies
	//
	iamSvc := iam.New(session)
	iamListPolicyParams := &iam.ListPoliciesInput{
		OnlyAttached: aws.Bool(true), // Required
		Scope:        aws.String("Local"),
	}

	iamListPolicyResp, iamListPolicyErr := iamSvc.ListPolicies(iamListPolicyParams)
	if iamListPolicyErr != nil {
		log.Fatalf("Couldn't list IAM policy: %v\n", iamListPolicyErr)
	}

	kmsData.IAMPolicies = make([]IAMPolicy, 0, len(iamListPolicyResp.Policies))

	//
	//Query for IAM local policy content
	//
	kmsRules := [14]string{"kms:Create", "kms:Describe", "kms:Enable", "kms:List", "kms:Put", "kms:Update", "kms:Revoke", "kms:Disable", "kms:Get", "kms:Delete", "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"}

	//Loop through each policy
	for _, iamPolicy := range iamListPolicyResp.Policies {
		iamGetPolicyParam := &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(*iamPolicy.Arn),
			VersionId: aws.String(*iamPolicy.DefaultVersionId),
		}

		// Query for policy content
		iamPolicyResp, iamPolicyErr := iamSvc.GetPolicyVersion(iamGetPolicyParam)
		if iamPolicyErr != nil {
			log.Fatalf("Couldn't get IAM policy content: %v\n", iamPolicyErr)
		}

		// Parse the policy
		iamPolicyMap, iamPolicyMapErr := url.ParseQuery("policy=" + *iamPolicyResp.PolicyVersion.Document)
		if iamPolicyMapErr != nil {
			log.Fatalf("Couldn't format IAM policy content: %v\n", iamPolicyErr)
		}

		iamPolicyStatement := iamPolicyMap.Get("policy")

		for _, kmsRule := range kmsRules {
			// If the value contains keyword of KMS rule
			if strings.Contains(iamPolicyStatement, kmsRule) {
				iamPolicyObj := IAMPolicy{Name: *iamPolicy.PolicyName,
					Statement: iamPolicyStatement,
				}

				kmsData.IAMPolicies = append(kmsData.IAMPolicies, iamPolicyObj)
				break
			}
		}
	}
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
func getAllKeyPolicy(svc *kms.KMS, keyId string) *kms.ListKeyPoliciesOutput {
	params := &kms.ListKeyPoliciesInput{
		KeyId: aws.String(keyId), // Required
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
func getKeyPolicyContent(svc *kms.KMS, keyId string, policyName string) *kms.GetKeyPolicyOutput {
	content_params := &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyId),      // Required
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
	Keys        []KMSKey    `json:"keys"`
	IAMPolicies []IAMPolicy `json:"iamPolicies"`
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
	MultiFactorAuthAge             int      `json:"MultiFactorAuthAge"`
}

type IAMPolicy struct {
	Name      string `json:name`
	Statement string `json:statement`
}

// type IAMPolicyStatement struct {
// 	Action                         []string `json:"action"`
// 	BypassPolicyLockoutSafetyCheck bool     `json:"BypassPolicyLockoutSafetyCheck"`
// 	MultiFactorAuthAge             int      `json:"MultiFactorAuthAge"`
// }
