package ioc

/*import (
	"encoding/json"
	"fmt"
	"strings"
)

// Provider cho otx.alienvault.com
type OtxProvider struct {
	APIKey string
	URL string
}

type OtxResult struct {
	Results []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Modified   string `json:"modified"`
		Created    string `json:"created"`
		Indicators []struct {
			ID        int    `json:"id"`
			Indicator string `json:"indicator"`
			Type      string `json:"type"`
		} `json:"indicators"`
		Tags []string `json:"tags"`
	} `json:"results"`
	Next string `json:"next"`
}

// Implement hàm GetPulsesSubscribed của IocProvider Interface
func (op OtxProvider)  GetPulsesSubscribed(limit string) ([]IocInfo, error) {
	pathAPI := fmt.Sprintf("%s", op.URL + "?limit=" + limit)
	fmt.Println(pathAPI)
	body, err := httpClient.getOtx(pathAPI)
	if err != nil {
		return []IocInfo{}, err
	}
	var otxResult OtxResult
	json.Unmarshal(body, &otxResult)
	return otxResult.asOtxInfo, nil
}

func (op OtxProvider) asOtxInfo() []IocInfo {
	results := make([]IocInfo, 0)
	for _, item := range op. {
		results = append(results, IocInfo{
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
}*/

