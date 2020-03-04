package main

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/pkg/errors"

	flag "github.com/spf13/pflag"
)

var (
	helpFlag    bool
	profileName string
	sess        *session.Session
)

func init() {
	flag.BoolVarP(&helpFlag, "help", "h", false, "show help message")
	flag.StringVarP(&profileName, "profile", "p", "default", "aws profile name")
	flag.Parse()
}

func main() {
	if helpFlag {
		flag.PrintDefaults()
		return
	}

	if err := handler(); err != nil {
		log.Fatal(err)
	}
}

func handler() error {
	log.Println("AWS Profile:", profileName)
	log.Println("Archiver Start !")
	sess = session.Must(session.NewSessionWithOptions(
		session.Options{Profile: profileName}),
	)

	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	for _, p := range partitions {
		for region, _ := range p.Regions() {
			if err := archiver(sess, region); err != nil {
				log.Println(err)
			}
		}
	}
	log.Println("Finished !")
	return nil
}

// archiver : archive findings by region
func archiver(sess *session.Session, region string) error {
	log.Println("*", region, "checking")
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
