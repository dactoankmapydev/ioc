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
			FirstSubmissionDate int   `json:"first_submission_date"`
			Exiftool            struct {
				FileType string `json:"FileType"`
			} `json:"exiftool"`
			LastAnalysisResults map[string]map[string]string `json:"last_analysis_results"`
		} `json:"attributes"`
		ContextAttributes struct {
			NotificationDate int `json:"notification_date"`
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
	for i, item := range vr.Data {
        pointAv :=vr.avp(i)
        if pointAv >= 13 {
			results = append(results, VrttInfo{
				Name:             strings.Join(item.Attributes.Names, ", "),
				Sha256:           item.Attributes.Sha256,
				Sha1:             item.Attributes.Sha1,
				Md5:              item.Attributes.Md5,
				Tags:             item.Attributes.Tags,
				FirstSubmit:      item.Attributes.FirstSubmissionDate,
				NotificationDate: item.ContextAttributes.NotificationDate,
				FileType:         item.Attributes.Exiftool.FileType,
				LastAnalysisResults: vr.avList(i),
				Detected: len(vr.avList(i)),
				Point: vr.avp(i),
			})
		}
	}

	return results
}

func difference(slice1 []string, slice2 []string) []string {
	var diff []string
	for i:=0; i< len(slice1) ; i++ {
		var isexit bool
		for j:=0; j< len(slice2) ; j++ {
			if slice1[i] == slice2[j]{
				isexit = true
				break;
			}
		}
		if isexit != true {
			diff = append(diff,slice1[i])
		}
	}
	return diff
}

func merge(avName []string, avType []string) map[string]string {
	avMap := make(map[string]string)
	for i:=0; i< len(avName); i++ {
		for j:=0; j< len(avType); j++ {
			avMap[avName[i]] = avType[i]
		}
	}
	return avMap
}

func avd(slice1 []string, map1 map[string]string) []string {
	var lastAv []string
	for i:=0; i< len(slice1) ; i++ {
		for k, v := range map1 {
			if slice1[i] == v{
				lastAv = append(lastAv, k)
			}
		}
		break
	}
	return lastAv
}

func point(slice1 []string) int {
	avHash := map[string]int{
		"Ad-Aware": 1,
		"AegisLab": 1,
		"ALYac": 2,
		"Antiy-AVL": 1,
		"Arcabit": 1,
		"Avast": 3,
		"AVG": 2,
		"Avira": 1,
		"Baidu": 2,
		"BitDefender": 3,
		"CAT-QuickHeal": 1,
		"Comodo": 2,
		"Cynet": 1,
		"Cyren": 1,
		"DrWeb": 1,
		"Emsisoft": 2,
		"eScan": 2,
		"ESET-NOD32": 3,
		"F-Secure": 2,
		"FireEye": 3,
		"Fortinet": 3,
		"GData": 1,
		"Ikarus": 2,
		"Kaspersky": 3,
		"MAX": 1,
		"McAfee": 3,
		"Microsoft": 3,
		"Panda": 2,
		"Qihoo-360": 2,
		"Rising": 1,
		"Sophos": 2,
		"TrendMicro": 3,
		"TrendMicro-HouseCall": 1,
		"ZoneAlarm by Check Point": 1,
		"Zoner": 1,
		"AhnLab - V3": 1,
		"BitDefenderTheta": 2,
		"Bkav": 1,
		"ClamAV": 3,
		"CMC": 1,
		"Gridinsoft": 1,
		"Jiangmin": 1,
		"K7AntiVirus": 1,
		"K7GW": 1,
		"Kingsoft": 1,
		"Malwarebytes": 3,
		"MaxSecure": 1,
		"McAfee - GW - Edition": 3,
		"NANO - Antivirus": 1,
		"Sangfor Engine Zero": 1,
		"SUPERAntiSpyware": 1,
		"Symantec": 3,
		"TACHYON": 1,
		"Tencent": 2,
		"TotalDefense": 1,
		"VBA32": 2,
		"VIPRE": 1,
		"ViRobot": 1,
		"Yandex": 3,
		"Zillya": 1,
		"Acronis": 3,
		"Alibaba": 2,
		"SecureAge APEX": 1,
		"Avast - Mobile": 2,
		"BitDefenderFalx": 3,
		"CrowdStrike Falcon": 3,
		"Cybereason": 3,
		"Cylance": 2,
		"eGambit": 1,
		"Elastic": 1,
		"Palo Alto Networks": 2,
		"SentinelOne (Static ML)": 1,
		"Symantec Mobile Insight": 3,
		"Trapmine": 1,
		"Trustlook": 1,
		"Webroot": 1,
	}
	var total int = 0
	for i:=0; i< len(slice1) ; i++ {
		for k, v := range avHash {
			if k == slice1[i]{
				total += v
			}
		}
	}
	return total
}

func (vr VirustotalResult) avList(i int) []string {
	results := make([]string, 0)
	avNames := make([]string, 0)

	avTypeClear := []string{"confirmed-timeout", "undetected", "timeout", "type-unsupported", "failure"}
	for index, item := range vr.Data {
		if index == i {
			totalAv := item.Attributes.LastAnalysisResults
			for avName, avType := range totalAv {
				avNames = append(avNames, avName)
				results = append(results, avType["category"])
			}
		}
	}
	av := merge(avNames, results)
	avDetect := difference(results, avTypeClear)
	nameAvDetect := avd(avDetect,av)
	return nameAvDetect
}

func (vr VirustotalResult) avp(i int) int {
	nameAvDetect := vr.avList(i)
	point := point(nameAvDetect)
	return point
}
