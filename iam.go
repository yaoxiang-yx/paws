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
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

type IAMBuilder struct{}

func (builder IAMBuilder) Name() string {
	return "IAM"
}

func (builder IAMBuilder) Populate(session *session.Session, tree *AWSTree) {

	svc := iam.New(session)
	users, err := svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		log.Fatalf("Couldn't list users: %v\n", err)
	}

	mfaMap := make(map[string]string)

	for _, mfa := range getMFAs(svc, users.Users) {
		mfaMap[*mfa.UserName] = *mfa.SerialNumber
	}

	iamData := IAMData{Users: make([]IAMUser, 0, len(users.Users))}

	for _, user := range users.Users {
		iamData.Users = append(iamData.Users, *buildUser(svc, user, mfaMap))
	}

	tree.Audit.IAM = &iamData
}

func buildUser(svc *iam.IAM, user *iam.User, mfaMap map[string]string) *IAMUser {
	u := &IAMUser{}
	u.ARN = *user.Arn
	u.CreatedAt = *user.CreateDate
	u.Path = *user.Path
	u.ID = *user.UserId
	u.Name = *user.UserName
	u.Keys = make([]IAMKey, 0, 1) // 1 is the conservative choice, we can always expand as needed.

	//
	// In order to find out when a password was created, we need to make another API call.  If the
	// user has no password, this method will return a 404.  This is OK and expected for API-only
	// users.
	//
	loginProfileOutput, err := svc.GetLoginProfile(&iam.GetLoginProfileInput{UserName: user.UserName})
	if err != nil && !strings.Contains(err.Error(), "404") {
		log.Fatalf("Couldn't get user login profile for %v: %v\n", user.UserName, err)
	}

	password := IAMUserPassword{}

	if loginProfileOutput.LoginProfile != nil && loginProfileOutput.LoginProfile.CreateDate != nil {
		password.CreatedAt = loginProfileOutput.LoginProfile.CreateDate
	}

	if user.PasswordLastUsed != nil {
		password.LastUsed = user.PasswordLastUsed
	}

	u.Password = password

	mfaSerial := mfaMap[u.Name]

	if len(mfaSerial) > 0 {
		if strings.HasPrefix(mfaSerial, "arn") {
			u.MFAType = "virtual"
		} else {
			u.MFAType = "hardware"
		}
	} else {
		u.MFAType = "none"
	}

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

		var iamLastUsed *IAMLastUsed

		if lastUsed != nil && lastUsed.AccessKeyLastUsed != nil {
			klu := lastUsed.AccessKeyLastUsed
			if klu.LastUsedDate != nil {
				iamLastUsed = &IAMLastUsed{}
				iamLastUsed.Date = *klu.LastUsedDate
				iamLastUsed.Region = *klu.Region
				iamLastUsed.ServiceName = *klu.ServiceName
			}
		}

		userKey := IAMKey{ID: *key.AccessKeyId,
			CreatedAt: *key.CreateDate,
			Status:    *key.Status,
			LastUsed:  iamLastUsed}
		// LastUsed: IAMLastUsed{Date: *lastUsed.AccessKeyLastUsed.LastUsedDate,
		// 	Region:      *lastUsed.AccessKeyLastUsed.Region,
		// 	ServiceName: *lastUsed.AccessKeyLastUsed.ServiceName}}
		user.Keys = append(user.Keys, userKey)
	}
}

//
// Query for all MFAs and return a slice.  The AWS Go SDK requires that
// we query for MFA on each user, there's no way to query for all hardware and
// virtual MFA tokens at once.
//
func getMFAs(svc *iam.IAM, users []*iam.User) []*iam.MFADevice {

	devices := make([]*iam.MFADevice, 0, 50)

	for _, user := range users {
		input := iam.ListMFADevicesInput{UserName: user.UserName}
		output, err := svc.ListMFADevices(&input)
		if err != nil {
			log.Fatalf("Couldn't query MFA device for user %v: %v\n", user.UserName, err)
		}
		devices = append(devices, output.MFADevices...)
	}

	return devices
}

// IAMData contains all IAM related data collected through the AWS account scan.
type IAMData struct {
	Users []IAMUser `json:"users"`
}

// IAMUser represents a single IAM user, as collected through an AWS account scan.
type IAMUser struct {
	ARN       string          `json:"arn"`
	CreatedAt time.Time       `json:"createdAt"`
	Path      string          `json:"path"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	MFAType   string          `json:"mfaType"`
	Keys      []IAMKey        `json:"keys"`
	Password  IAMUserPassword `json:"password"`
}

// IAMKey is an access key used by an AWS entity
type IAMKey struct {
	ID        string       `json:"id"`
	CreatedAt time.Time    `json:"createdAt"`
	Status    string       `json:"status"`
	LastUsed  *IAMLastUsed `json:"lastUsed"`
}

type IAMLastUsed struct {
	Date        time.Time `json:"date"`
	Region      string    `json:"region"`
	ServiceName string    `json:"serviceName"`
}

type IAMUserPassword struct {
	CreatedAt *time.Time `json:"createdAt"`
	LastUsed  *time.Time `json:"lastUsed"`
}
