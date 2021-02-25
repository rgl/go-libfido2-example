package main

import (
	"encoding/hex"
	"log"

	libfido2 "github.com/keys-pub/go-libfido2"
)

func main() {
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}

	for _, loc := range locs {
		log.Printf("%+v\n", loc)
		device, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			log.Fatal(err)
		}

		hidInfo, err := device.CTAPHIDInfo()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("CTAPHIDInfo: %+v\n", hidInfo)

		info, err := device.Info()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Info: %+v\n", info)
	}

	if len(locs) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	info, err := device.Info()
	if err != nil {
		log.Fatal(err)
	}

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)
	salt := libfido2.RandBytes(32)
	pin := "12345"

	for _, o := range info.Options {
		if o.Name == "clientPin" && o.Value == libfido2.False {
			pin = ""
		}
	}

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: "keys.pub",
		},
		libfido2.User{
			ID:   userID,
			Name: "gabriel",
		},
		libfido2.ES256, // Algorithm
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.True,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attestation:\n")
	log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
	log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(attest.CredentialID))
	log.Printf("Type: %s\n", attest.CredentialType)
	log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))

	assertion, err := device.Assertion(
		"keys.pub",
		cdh,
		attest.CredentialID,
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UP:         libfido2.True,
			HMACSalt:   salt,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assertion:\n")
	log.Printf("%s\n", hex.EncodeToString(assertion.AuthData))
	log.Printf("%s\n", hex.EncodeToString(assertion.HMACSecret))
	log.Printf("%s\n", hex.EncodeToString(assertion.Sig))
}
