package ioc

import (
	"encoding/json"
	"fmt"
)

// Provider cho virustotal.com
type VirustotalProvider struct {
	APIKey string
	API string
}

type VirustotalResult struct {
	Data []VirustotalInfo `json:"data"`
}

type VirustotalInfo struct {
	Name string `json:"name"`
	/*Sha256 string `json:"sha256"`
	Sha1 string `json:"sha1"`
	Md5 string `json:"md5"`
	Tags []string `json:"tags,string"`
	FirstSubmit string `json:"first_submit"`
	NotificationDate string `json:"notification_date"`
	FileType string `json:"file_type"`*/
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
func (vp VirustotalProvider)  Get(limit string) (string, error) {
	pathAPI := fmt.Sprintf("%s", vp.API + "?limit=" + limit)
	fmt.Println(pathAPI)
	body, err := httpClient.getVirustotal(pathAPI)
	if err != nil {
		return "", err
	}

	var result VirustotalResult
	json.Unmarshal(body, &result)
	fmt.Println("data", result.Data[0])
	return result.asIocInfo().Name, nil
}

func (vr VirustotalResult) asIocInfo() IocInfo {
	return IocInfo{
		Name:             vr.name(),
		/*Sha256:           vr.sha256(),
		Sha1:             vr.sha1(),
		Md5:              vr.md5(),
		Tags:             vr.tags(),
		FirstSubmit:      vr.firstSubmit(),
		NotificationDate: vr.notificationDate(),
		FileType:         vr.fileType(),*/
	}
}

func (vr VirustotalResult) name() string {
	return vr.Data[0].Name
}

/*func (vr VirustotalResult) sha256() string {
	return vr.Data[0].Sha256
}

func (vr VirustotalResult) sha1() string {
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

