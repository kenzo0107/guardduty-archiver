package main

import (
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/pkg/errors"
)

var (
	profileName string = os.Getenv("AWS_PROFILE")
	sess        *session.Session
)

func init() {
	if profileName == "" {
		profileName = "default"
	}
}

func main() {
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

		archiveFindingsOutput, err := guarddutyCli.ArchiveFindings(&guardduty.ArchiveFindingsInput{
			DetectorId: detectorID,
			FindingIds: listFindingsOutput.FindingIds,
		})
		if err != nil {
			return errors.Wrap(err, "on ArchiveFindings")
		}
		log.Println("archiveFindingsOutput", archiveFindingsOutput)
	}
	return nil
}
