package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/sts"
	. "github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	flag "github.com/spf13/pflag"
)

var (
	help    bool
	profile string
	sess    *session.Session
)

func init() {
	flag.BoolVarP(&help, "help", "h", false, "show help message")
	flag.StringVarP(&profile, "profile", "p", "default", "aws profile name")
	flag.Parse()
}

func main() {
	if help {
		flag.PrintDefaults()
		return
	}

	if err := handler(); err != nil {
		fmt.Println(Red(err))

	}
}

func handler() error {
	log.Println("Archiver Start !")
	sess = session.Must(session.NewSessionWithOptions(
		session.Options{
			Profile:                 profile,
			AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
			SharedConfigState:       session.SharedConfigEnable,
		}),
	)

	stsCli := sts.New(sess)
	r, _ := stsCli.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	fmt.Println("archive executor information:")
	fmt.Println(r)

	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	for _, p := range partitions {
		for region := range p.Regions() {
			if err := archiver(sess, region); err != nil {
				fmt.Println(Red(err))
			}
		}
	}
	log.Println("Finished !")
	return nil
}

// archiver : archive findings by region
func archiver(sess *session.Session, region string) error {
	defer fmt.Println("*", region, "checked")

	guarddutyCli := guardduty.New(
		sess,
		aws.NewConfig().WithRegion(region),
	)
	listDetectorOutput, err := guarddutyCli.ListDetectors(&guardduty.ListDetectorsInput{})
	if err != nil {
		return errors.Wrap(err, "on ListDetectors")
	}

	for _, detectorID := range listDetectorOutput.DetectorIds {
		listFindingsOutput, err := guarddutyCli.ListFindings(&guardduty.ListFindingsInput{
			DetectorId: detectorID,
		})
		if err != nil {
			return errors.Wrap(err, "on ListFindings")
		}

		if _, err := guarddutyCli.ArchiveFindings(&guardduty.ArchiveFindingsInput{
			DetectorId: detectorID,
			FindingIds: listFindingsOutput.FindingIds,
		}); err != nil {
			return errors.Wrap(err, "on ArchiveFindings")
		}
	}
	return nil
}

func makeSession(profile string) (*session.Session, string, error) {
	if profile == "" {
		profile = "default"
		if os.Getenv("AWS_PROFILE") != "" {
			profile = os.Getenv("AWS_PROFILE")
		}
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		Profile:           profile,
		SharedConfigState: session.SharedConfigEnable,
	})
	return sess, profile, err
}
