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
			LastAnalysisResults: vr.av(),
		})
	}

	return results
}

func difference(slice1 []string, slice2 []string) []string {
	var diff []string

	// Loop two times, first to find slice1 strings not in slice2,
	// second loop to find slice2 strings not in slice1
	for i := 0; i < 2; i++ {
		for _, s1 := range slice1 {
			found := false
			for _, s2 := range slice2 {
				if s1 == s2 {
					found = true
					break
				}
			}
			// String not found. We add it to return slice
			if !found {
				diff = append(diff, s1)
			}
		}
		// Swap the slices, only if it was the first loop
		if i == 0 {
			slice1, slice2 = slice2, slice1
		}
	}

	return diff
}

func (vr VirustotalResult) av() []string {
	/*avHash := map[string]int{
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
	}*/
	results := make([]string, 0)
	avTypeClear := []string{"undetected", "timeout", "type-unsupported", "confirmed-timeout"}
	for _, item := range vr.Data {
		totalAv := item.Attributes.LastAnalysisResults
		for _, avType := range totalAv {
			//if avType["category"]
			results = append(results, avType["category"])
		}
	}

	avDetect := difference(results, avTypeClear)
	fmt.Println(results, avDetect, len(avDetect))
	return results
}
