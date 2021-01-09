package ioc

import (
	"encoding/json"
	"fmt"
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
/*func (vp VirustotalProvider)  GetHuntingNotificationFiles(limit, cursor, filter string) (IocInfo, error) {
	pathAPI := fmt.Sprintf("%s%s%s%s", vp.API, limit, cursor, filter)
	fmt.Println(pathAPI)
	body, err := httpClient.getVirustotal(pathAPI)
	if err != nil {
		return IocInfo{}, err
	}
	var result VirustotalResult
	json.Unmarshal(body, &result)
    return result.asIocInfo(), nil
}*/
func (vp VirustotalProvider)  Get(limit string) (IocInfo, error) {
	pathAPI := fmt.Sprintf("%s", vp.URL + "?limit=" + limit)
	fmt.Println(pathAPI)
	body, err := httpClient.getVirustotal(pathAPI)
	if err != nil {
		return IocInfo{}, err
	}
	var result VirustotalResult
	json.Unmarshal(body, &result)
	return result.asIocInfo(), nil
}

func (vr VirustotalResult) asIocInfo() IocInfo {
	return IocInfo{
		Name:             vr.name(),
		Sha256:           vr.sha256(),
		Sha1:             vr.sha1(),
		Md5:              vr.md5(),
		Tags:             vr.tags(),
		FirstSubmit:      vr.firstSubmit(),
		NotificationDate: vr.notificationDate(),
		FileType:         vr.fileType(),
	}
}

func (vr VirustotalResult) name() string {
	fmt.Println("name", vr.Data[0].Attributes.Names[0])
	if len(vr.Data[0].Attributes.Names) == 0 {
		return ""
	}
	return vr.Data[0].Attributes.Names[0]
}

func (vr VirustotalResult) sha256() string {
	fmt.Println("sha256", vr.Data[0].Attributes.Sha256)
	return vr.Data[0].Attributes.Sha256
}

func (vr VirustotalResult) sha1() string {
	fmt.Println("sha1", vr.Data[0].Attributes.Sha1)
	return vr.Data[0].Attributes.Sha1
}

func (vr VirustotalResult) md5() string {
	fmt.Println("md5", vr.Data[0].Attributes.Md5)
	return vr.Data[0].Attributes.Md5
}

func (vr VirustotalResult) tags() []string {
	fmt.Println("tags", vr.Data[0].Attributes.Tags)
	return vr.Data[0].Attributes.Tags
}

func (vr VirustotalResult) firstSubmit() string {
	fmt.Println("submit", vr.Data[0].Attributes.FirstSubmissionDate)
	return vr.Data[0].Attributes.FirstSubmissionDate
}

func (vr VirustotalResult) notificationDate() string {
	fmt.Println("notidate", vr.Data[0].ContextAttributes.NotificationDate)
	return vr.Data[0].ContextAttributes.NotificationDate
}

func (vr VirustotalResult) fileType() string {
	fmt.Println("type", vr.Data[0].Attributes.Exiftool.FileType)
	return vr.Data[0].Attributes.Exiftool.FileType
}
