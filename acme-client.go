package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/acme"
)

var (
	DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	accountName  string
	baseDir      = "./"
	client       acme.Client
)

func main() {
	app := cli.NewApp()
	app.Name = "acme-client"
	app.Usage = "ACME client"
	app.Authors = []*cli.Author{
		{Name: "Cesar Kuroiwa"},
	}
	app.Before = setupClient
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "name",
			Aliases:     []string{"n"},
			Usage:       "Account name",
			Destination: &accountName,
		},
		&cli.StringFlag{
			Name:        "base-dir",
			Aliases:     []string{"b"},
			Usage:       "Set base dir",
			Destination: &baseDir,
			Value:       baseDir,
		},
	}
	app.Commands = []*cli.Command{
		{
			Name:  "register",
			Usage: "Create a new account",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "name",
					Aliases:     []string{"n"},
					Usage:       "Account name",
					Destination: &accountName,
				},
			},
			Action: register,
		},
		{
			Name:   "get-account",
			Usage:  "Get an existing account",
			Action: getAccount,
			Before: validateAccount,
		},
		{
			Name:  "create-order",
			Usage: "Create a new order",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hostname",
					Usage: "hostname",
				},
			},
			Action: createOrder,
			Before: validateOrder,
		},
		{
			Name:  "get-order",
			Usage: "Get order",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hostname",
					Usage: "hostname",
				},
			},
			Action: createOrder,
			Before: validateOrder,
		},
		{
			Name:  "accept-challenge",
			Usage: "Challenge accepted!",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hostname",
					Usage: "hostname",
				},
			},
			Action: acceptChallenge,
			Before: validateOrder,
		},
		{
			Name:  "gen-cert",
			Usage: "Generate certificate",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "hostname",
					Usage: "hostname",
				},
			},
			Action: genCert,
			Before: validateOrder,
		},
		{
			Name:  "get-cert",
			Usage: "Get certificate",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "url",
					Aliases: []string{"u"},
					Usage:   "Certificate URL",
				},
			},
			Action: getCert,
			Before: validateAccount,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func setupClient(ctx *cli.Context) error {
	client = acme.Client{
		DirectoryURL: DirectoryURL,
	}

	return nil
}

func validateAccount(ctx *cli.Context) error {
	if accountName == "" {
		return fmt.Errorf("account name not informed")
	}

	privateKey, err := loadAccountKey()
	if err != nil {
		return fmt.Errorf("error loading account key: %s", err)
	}

	accountKey := privateKey.(*ecdsa.PrivateKey)
	client.Key = accountKey
	return nil
}

func validateOrder(ctx *cli.Context) error {
	if err := validateAccount(ctx); err != nil {
		return err
	}

	hostname := ctx.String("hostname")
	if hostname == "" {
		return fmt.Errorf("hostname is mandatory")
	}
	return nil
}

func register(ctx *cli.Context) error {
	accountkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	client.Key = accountkey

	account, err := client.Register(context.Background(), &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		return fmt.Errorf("error creating account: %s", err)
	}

	if err := saveAccountKey(accountkey); err != nil {
		return fmt.Errorf("error saving account key: %s", err)
	}

	fmt.Printf("Account created successfully\n")
	printAccount(account)
	return nil
}

func getAccount(ctx *cli.Context) error {
	privateKey, err := loadAccountKey()
	if err != nil {
		log.Fatal(err)
	}

	accountKey := privateKey.(*ecdsa.PrivateKey)
	client := acme.Client{
		Key:          accountKey,
		DirectoryURL: DirectoryURL,
	}

	account, err := client.GetReg(context.Background(), "")
	if err != nil {
		log.Fatalf("error loading account: %s", err)
	}

	printAccount(account)
	return nil
}

func createOrder(ctx *cli.Context) error {
	hostname := ctx.String("hostname")
	order, err := getOrder(hostname)
	if err != nil {
		return err
	}

	printOrder(order, hostname)
	if order.Status != acme.StatusPending {
		return nil
	}

	authorization, err := client.GetAuthorization(context.Background(), order.AuthzURLs[0])
	if err != nil {
		return fmt.Errorf("error getting authorization: %s", err)
	}

	for _, challenge := range authorization.Challenges {
		if challenge.Type == "http-01" {
			keyAuth, err := client.HTTP01ChallengeResponse(challenge.Token)
			if err != nil {
				return fmt.Errorf("error on HTTP challenge: %s", err)
			}
			fmt.Printf("HTTP challenge: %s %s\n", challenge.Token, keyAuth)
		}
	}

	return nil
}

func acceptChallenge(ctx *cli.Context) error {
	hostname := ctx.String("hostname")
	order, err := getOrder(hostname)
	if err != nil {
		return err
	}

	if order.Status != acme.StatusPending {
		fmt.Printf("No pending challenge for %s\n", hostname)
		return nil
	}

	authorization, err := client.GetAuthorization(context.Background(), order.AuthzURLs[0])
	if err != nil {
		log.Fatalf("error getting authorization: %s", err)
	}

	for _, challenge := range authorization.Challenges {
		if challenge.Type == "http-01" {
			if _, err := client.Accept(context.Background(), challenge); err != nil {
				log.Fatalf("error accepting challenge: %s", err)
			}
		}
	}

	return nil
}

func genCert(ctx *cli.Context) error {
	hostname := ctx.String("hostname")
	order, err := getOrder(hostname)
	if err != nil {
		return err
	}

	if order.Status != acme.StatusReady {
		return fmt.Errorf("order not ready")
	}

	certificateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating RSA key: %s", err)
	}

	certificateRequest := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	certificateRequest.Subject.CommonName = hostname
	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, certificateKey)
	if err != nil {
		return fmt.Errorf("error creating CSR: %s", err)
	}

	der, url, err := client.CreateOrderCert(context.Background(), order.FinalizeURL, csr, false)
	if err != nil {
		return fmt.Errorf("error creating certificate: %s", err)
	}

	if err := saveCertificate(hostname, certificateKey, der[0]); err != nil {
		return fmt.Errorf("error saving certificate: %s", err)
	}

	fmt.Println("Certificate URL:", url)

	return nil
}

func getCert(ctx *cli.Context) error {
	url := ctx.String("url")
	der, err := client.FetchCert(context.Background(), url, false)
	if err != nil {
		return fmt.Errorf("error getting certificate: %s", err)
	}

	pemBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der[0],
	}

	certPEM := pem.EncodeToMemory(&pemBlock)
	fmt.Println(string(certPEM))
	return nil
}

func saveAccountKey(key crypto.PrivateKey) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	pemBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	os.Mkdir(path.Join(baseDir, accountName), os.ModePerm)
	filepath := path.Join(baseDir, accountName, accountName+".key")
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	pem.Encode(file, &pemBlock)
	file.Sync()
	file.Close()
	return nil
}

func loadAccountKey() (crypto.PrivateKey, error) {
	filepath := path.Join(baseDir, accountName, accountName+".key")
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func getOrder(hostname string) (*acme.Order, error) {
	authzID := acme.AuthzID{
		Type:  "dns",
		Value: hostname,
	}
	order, err := client.AuthorizeOrder(context.Background(), []acme.AuthzID{authzID})
	if err != nil {
		return nil, fmt.Errorf("error getting order: %s", err)
	}

	return order, nil
}

func printAccount(account *acme.Account) {
	buf := bytes.NewBufferString(fmt.Sprintf("Account %s\n", accountName))
	buf.WriteString(fmt.Sprintf("  URI: %s\n", account.URI))
	buf.WriteString(fmt.Sprintf("  Status: %s\n", account.Status))
	buf.WriteString(fmt.Sprintf("  Orders URL: %s\n", account.OrdersURL))
	fmt.Println(buf.String())

}

func printOrder(order *acme.Order, hostname string) {
	buf := bytes.NewBufferString(fmt.Sprintf("Order %s\n", hostname))
	buf.WriteString(fmt.Sprintf("  URI: %s\n", order.URI))
	buf.WriteString(fmt.Sprintf("  Status: %s\n", order.Status))
	buf.WriteString(fmt.Sprintf("  Expires: %s\n", order.Expires.Format("2006-01-02 15:04:05")))
	fmt.Println(buf.String())
}

func saveCertificate(hostname string, key crypto.PrivateKey, der []byte) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	os.Mkdir(path.Join(baseDir, accountName, hostname), os.ModePerm)
	keyPath := path.Join(baseDir, accountName, hostname, hostname+".key")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	pem.Encode(keyFile, &keyPEM)
	keyFile.Sync()
	keyFile.Close()

	certPEM := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}

	certPath := path.Join(baseDir, accountName, hostname, hostname+".crt")
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	pem.Encode(certFile, &certPEM)
	certFile.Sync()
	certFile.Close()
	return nil
}
