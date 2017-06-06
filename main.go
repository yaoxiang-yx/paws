/*
Copyright 2017 SourceClear Inc
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/continuous-security/paws/tree"
)

func main() {
	sess, err := session.NewSession(&aws.Config{
		// TODO: Jason to remove hardcoded region
		Region: aws.String("us-east-1")},
	)
	if err != nil {
		log.Fatalf("Couldn't set up session: %v\n", err)
	}

	iamData, err := tree.BuildIAM(sess)
	if err != nil {
		log.Fatalf("Couldn't build IAM data: %v\n", err)
	}

	// TODO: Create KMS, EC2, and RDS data trees and populate
	// them here, using the IAM code as a base.

	auditData := tree.AuditData{IAM: iamData}
	tree := tree.AWSTree{Audit: auditData}

	bytes, err := json.MarshalIndent(tree, "", "  ")
	fmt.Printf("\n%v\n", string(bytes))
}
