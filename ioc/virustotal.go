package ioc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Provider cho virustotal.com
type VirustotalProvider struct {
	APIKey string
	URL string
}

type VirustotalResult struct {
	Data []struct {
		Attributes struct {
			Names               []string `json:"names"`
			Md5                 string   `json:"md5"`
			Sha1                string   `json:"sha1"`
			Sha256              string   `json:"sha256"`
			Tags                []string `json:"tags"`
			FirstSubmissionDate string   `json:"first_submission_date"`
			Exiftool            struct {
				FileType string `json:"FileType"`
			} `json:"exiftool"`
			LastAnalysisResults struct {
			} `json:"last_analysis_results"`
		} `json:"attributes"`
		ContextAttributes struct {
			NotificationDate string `json:"notification_date"`
		} `json:"context_attributes"`
	} `json:"data"`
}

// Implement hàm GetHuntingNotificationFiles của IocProvider Interface
func (vp VirustotalProvider)  GetHuntingNotificationFiles(limit string) ([]VrttInfo, error) {
	pathAPI := fmt.Sprintf("%s", vp.URL + "?limit=" + limit)
	fmt.Println(pathAPI)
	body, err := httpClient.getVirustotal(pathAPI)
	if err != nil {
		return []VrttInfo{}, err
	}
	var result VirustotalResult
	json.Unmarshal(body, &result)
	return result.asVrttInfo(), nil
}

func (vr VirustotalResult) asVrttInfo() []VrttInfo {
	results := make([]VrttInfo, 0)
	for _, item := range vr.Data {
		results = append(results, VrttInfo{
			Name:             strings.Join(item.Attributes.Names, ", "),
			Sha256:           item.Attributes.Sha256,
			Sha1:             item.Attributes.Sha1,
			Md5:              item.Attributes.Md5,
			Tags:             item.Attributes.Tags,
			FirstSubmit:      item.Attributes.FirstSubmissionDate,
			NotificationDate: item.ContextAttributes.NotificationDate,
			FileType:         item.Attributes.Exiftool.FileType,
		})
	}

	return results
}

/*func (vr VirustotalResult) sha256() []string {
	sha256 := make([]string, 0)
	for _, item := range vr.Data {
		sha256 = append(sha256, item.Attributes.Sha256)
	}
	return sha256
}

/*func (vr VirustotalResult) name() string {
	if len(vr.Data[0].Attributes.Names) == 0 {
		return ""
	}
	return vr.Data[0].Attributes.Names[0]
}

func (vr VirustotalResult) sha1() string {
	return vr.Data[0].Attributes.Sha1
}

func (vr VirustotalResult) md5() string {
	return vr.Data[0].Attributes.Md5
}

func (vr VirustotalResult) tags() []string {
	return vr.Data[0].Attributes.Tags
}

func (vr VirustotalResult) firstSubmit() string {
	return vr.Data[0].Attributes.FirstSubmissionDate
}

func (vr VirustotalResult) notificationDate() string {
	return vr.Data[0].ContextAttributes.NotificationDate
}

func (vr VirustotalResult) fileType() string {
	return vr.Data[0].Attributes.Exiftool.FileType
}*/
