package crawler

import (
	"encoding/json"
	"fmt"
	"ioc-provider/model"
	"math"
)

// Provider cho otx
type OtxProvider struct {
	APIKey string
}

type OtxResult struct {
	Results []struct {
		PulseID              string `json:"id"`
		Name                 string `json:"name"`
		Description          string `json:"description"`
		AuthorName           string `json:"author_name"`
		Modified             string `json:"modified"`
		Created              string `json:"created"`
		Tags                 []string `json:"tags"`
		TargetedCountries    []string `json:"targeted_countries"`
		Industries           []string `json:"industries"`
		MalwareFamilies      []string `json:"malware_families"`
		AttackIds            []string `json:"attack_ids"`
		References           string `json:"references"`
		Indicators []struct {
			IocID             string    `json:"id"`
			Ioc               string `json:"indicator"`
			IocType           string `json:"type"`
			Created           string `json:"created"`
		} `json:"indicators"`
	} `json:"results"`
	Count                     int64 `json:"count"`
}

// Implement hàm Subscribed của IocRepo Interface
func (op OtxProvider) Subscribed() {
	post_list := make([]model.Post, 0)
	ioc_list := make([]model.Indicator, 0)
	totalPage := TotalPageOtx()
	for page := 1; page <= totalPage; page ++ {
		//pathAPI := fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=2019-01-01T00:00:00.000+00:00&limit=50&page=%d", page)
		pathAPI := fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=%d", page)
		fmt.Println("pathAPI->",pathAPI)
		body, err := httpClient.getOtx(pathAPI)
		if err != nil {
			return
		}
		var or OtxResult
		json.Unmarshal(body, &or)

		for _, item := range or.Results {
			post := model.Post{
				PulseID:           item.PulseID,
				Name:              item.Name,
				Description:       item.Description,
				AuthorName:        item.AuthorName,
				Modified:          item.Modified,
				Created:           item.Created,
				TargetedCountries: item.TargetedCountries,
				Industries:        item.Industries,
				MalwareFamilies:   item.MalwareFamilies,
				AttackIds:         item.AttackIds,
				References:        item.References,
				Category:          item.Tags,
			}
			post_list = append(post_list, post)
			fmt.Println("post->", post)

			for _, value := range item.Indicators {
				var indicator = model.Indicator{
					IocID:       value.IocID,
					Ioc:         value.Ioc,
					IocType:     value.IocType,
					CreatedTime: value.Created,
					CrawledTime: "",
					Source:      "otx",
					Category:    item.Tags,
				}
				ioc_list = append(ioc_list, indicator)
				fmt.Println("indicator->", indicator)
			}

		}
	}
	fmt.Println("len post_list->", len(post_list))
	fmt.Println("len ioc_list->",len(ioc_list))
}

func TotalPageOtx() int {
	//pathAPI := fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=2019-01-01T00:00:00.000+00:00&limit=50")
	pathAPI := fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50")
	fmt.Println("pathAPI->",pathAPI)
	body, err := httpClient.getOtx(pathAPI)
	if err != nil {
		return 0
	}
	var or OtxResult
	json.Unmarshal(body, &or)
	countPost := or.Count
	totalPage := math.Ceil(float64(countPost)/float64(50))
	fmt.Println("totalPage->",int(totalPage))
	return int(totalPage)
}
