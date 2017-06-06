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

package tree

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

func BuildIAM(session *session.Session) (IAMData, error) {

	svc := iam.New(session)
	users, err := svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		log.Fatalf("Couldn't list users: %v\n", err)
	}

	// keys, err := svc.ListAccessKeys(&iam.ListAccessKeysInput{})
	// if err != nil {
	// 	log.Fatalf("Couldn't list access keys: %v\n", err)
	// }

	iamData := IAMData{Users: make([]IAMUser, 0, len(users.Users))}

	for _, user := range users.Users {
		iamData.Users = append(iamData.Users, *buildUser(svc, user))
	}

	return iamData, nil
}

func buildUser(svc *iam.IAM, user *iam.User) *IAMUser {
	u := &IAMUser{}
	u.ARN = *user.Arn
	u.CreatedAt = *user.CreateDate
	u.Path = *user.Path
	u.ID = *user.UserId
	u.Name = *user.UserName
	u.Keys = make([]IAMKey, 0, 1) // 1 is the conservative choice, we can always expand as needed.

	buildKeys(svc, u)

	return u
}

func buildKeys(svc *iam.IAM, user *IAMUser) {
	keys, err := svc.ListAccessKeys(&iam.ListAccessKeysInput{UserName: &user.Name})
	if err != nil {
		log.Fatalf("Couldn't list access keys: %v\n", err)
	}

	for _, key := range keys.AccessKeyMetadata {
		lastUsed, err := svc.GetAccessKeyLastUsed(&iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
		if err != nil {
			log.Fatalf("Couldn't determine when key was last used: %v\n", err)
		}

		userKey := IAMKey{ID: *key.AccessKeyId,
			CreatedAt: *key.CreateDate,
			Status:    *key.Status,
			LastUsed: IAMLastUsed{Date: *lastUsed.AccessKeyLastUsed.LastUsedDate,
				Region:      *lastUsed.AccessKeyLastUsed.Region,
				ServiceName: *lastUsed.AccessKeyLastUsed.ServiceName}}
		user.Keys = append(user.Keys, userKey)
	}
}

// ListMFA

// func getVirtualMFAs(svc *iam.IAM) []*iam.VirtualMFADevice {

// 	maxItems := int64(1000)

// 	devices := make([]*iam.VirtualMFADevice, 50)

// 	remaining := true
// 	marker := ""

// 	for remaining {
// 		var input iam.ListVirtualMFADevicesInput
// 		if len(marker) > 0 {
// 			input = iam.ListVirtualMFADevicesInput{Marker: &marker, MaxItems: &maxItems}
// 		} else {
// 			input = iam.ListVirtualMFADevicesInput{MaxItems: &maxItems}
// 		}

// 		output, err := svc.ListVirtualMFADevices(&input)

// 		if err != nil {
// 			log.Fatalf("Couldn't get Virtual MFA devices: %v\n", err)
// 		}
// 		devices = append(devices, output.VirtualMFADevices...)
// 		if output.Marker != nil {
// 			marker = *output.Marker
// 		}
// 		remaining = *output.IsTruncated
// 	}

// 	for _, d := range devices {
// 		println(d)
// 	}

// 	return devices
// }

// AuditData represents the data collected through an AWS account scan.

// IAMData contains all IAM related data collected through the AWS account scan.
type IAMData struct {
	Users []IAMUser `json:"users"`
}

// IAMUser represents a single IAM user, as collected through an AWS account scan.
type IAMUser struct {
	ARN       string    `json:"arn"`
	CreatedAt time.Time `json:"createdAt"`
	Path      string    `json:"path"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MFAType   string    `json:"mfaType"`
	Keys      []IAMKey  `json:"keys"`
}

// IAMKey is an access key used by an AWS entity
type IAMKey struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"createdAt"`
	Status    string      `json:"status"`
	LastUsed  IAMLastUsed `json:"lastUsed"`
}

type IAMLastUsed struct {
	Date        time.Time `json:"date"`
	Region      string    `json:"region"`
	ServiceName string    `json:"serviceName"`
}
