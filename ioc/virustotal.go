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
			//Names               []string `json:"names"`
			//Md5                 string        `json:"md5"`
			//Sha1                string        `json:"sha1"`
			Sha256              string        `json:"sha256"`
			//Tags                []string `json:"tags"`
			//FirstSubmissionDate int           `json:"first_submission_date"`
			//Exiftool            struct {
			//	FileType string `json:"FileType"`
			//} `json:"exiftool"`
			//LastAnalysisResults struct {
			//} `json:"last_analysis_results"`
		} `json:"attributes"`
		//ContextAttributes struct {
		//	NotificationDate int `json:"notification_date"`
		//} `json:"context_attributes"`
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
	fmt.Println("func get limit")
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
	fmt.Println("func asIocInfo")
	return IocInfo{
		//Name:             vr.name(),
		Sha256:           vr.sha256(),
		/*Sha1:             vr.sha1(),
		Md5:              vr.md5(),
		Tags:             vr.tags(),
		FirstSubmit:      vr.firstSubmit(),
		NotificationDate: vr.notificationDate(),
		FileType:         vr.fileType(),*/
	}
}

/*func (vr VirustotalResult) name() string {
	return vr.Data[0].Attributes.Names[0]
}*/

func (vr VirustotalResult) sha256() string {
	fmt.Println("func get sha26")
	fmt.Println("sha256", vr.Data[0].Attributes.Sha256)
	return vr.Data[0].Attributes.Sha256
}

/*func (vr VirustotalResult) sha1() string {
	return vr.Data[0].Sha1
}

func (vr VirustotalResult) md5() string {
	return vr.Data[0].Md5
}

func (vr VirustotalResult) tags() []string {
	return vr.Data[0].Tags
}

func (vr VirustotalResult) firstSubmit() string {
	return vr.Data[0].FirstSubmit
}

func (vr VirustotalResult) notificationDate() string {
	return vr.Data[0].NotificationDate
}

func (vr VirustotalResult) fileType() string {
	return vr.Data[0].FileType
}*/
