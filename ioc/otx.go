package ioc

import (
	"encoding/json"
	"fmt"
)

// Provider cho otx.alienvault.com
type OtxProvider struct {
	APIKey string
	API string
}

type OtxlResult struct {
	Data []OtxInfo `json:"data"`
}

type OtxInfo struct {
	Name string `json:"name"`
	/*Sha256 string `json:"sha256"`
	Sha1 string `json:"sha1"`
	Md5 string `json:"md5"`
	Tags []string `json:"tags,string"`
	FirstSubmit string `json:"first_submit"`
	NotificationDate string `json:"notification_date"`
	FileType string `json:"file_type"`*/
}

// Implement hàm GetPulsesSubscribed của IocProvider Interface
/*func (op OtxProvider)  GetPulsesSubscribed(limit, page, modifiedSince string) (IocInfo, error) {
	pathAPI := fmt.Sprintf("%s%s%s%s", op.API, limit, page, modifiedSince)
	body, err := httpClient.getOtx(pathAPI)
	if err != nil {
		return IocInfo{}, err
	}
	var result OtxlResult
	json.Unmarshal(body, &result)
	return result.asIocInfo(), nil
}*/
func (op OtxProvider)  Get(limit string) (string, error) {
	pathAPI := fmt.Sprintf("%s", op.API + "?limit=" + limit)
	fmt.Println(pathAPI)
	body, err := httpClient.getOtx(pathAPI)
	if err != nil {
		return "", err
	}
	var result OtxlResult
	json.Unmarshal(body, &result)
	fmt.Println(result)
	return result.asIocInfo().Name, nil
}

func (or OtxlResult) asIocInfo() IocInfo {
	return IocInfo{
		Name:             or.name(),
		/*Sha256:           or.sha256(),
		Sha1:             or.sha1(),
		Md5:              or.md5(),
		Tags:             or.tags(),
		FirstSubmit:      or.firstSubmit(),
		NotificationDate: or.notificationDate(),
		FileType:         or.fileType(),*/
	}
}

func (or OtxlResult) name() string {
	return or.Data[0].Name
}

/*func (or OtxlResult) sha256() string {
	return or.Data[0].Sha256
}

func (or OtxlResult) sha1() string {
	return or.Data[0].Sha1
}

func (or OtxlResult) md5() string {
	return or.Data[0].Md5
}

func (or OtxlResult) tags() []string {
	return or.Data[0].Tags
}

func (or OtxlResult) firstSubmit() string {
	return or.Data[0].FirstSubmit
}

func (or OtxlResult) notificationDate() string {
	return or.Data[0].NotificationDate
}

func (or OtxlResult) fileType() string {
	return or.Data[0].FileType
}*/
