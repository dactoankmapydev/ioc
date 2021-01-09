package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	ioc "ioc-provider/ioc"
	"log"
	"net/http"
	"os"
)
// Danh sách các Provider
type ProviderList []ioc.IocProvider

type IocData struct {
	//Name string `json:"name"`
	Sha256 string `json:"sha256"`
	/*Sha1 string `json:"sha1"`
	Md5 string `json:"md5"`
	Tags []string `json:"tags,string"`
	FirstSubmit string `json:"first_submit"`
	NotificationDate string `json:"notification_date"`
	FileType string `json:"file_type"`*/
}

// Lấy dữ liệu
func (list ProviderList) iocData(limit string) (string, error) {
	// Tạo channel để hứng data và error trả về từ routine
	chanData := make(chan string)
	chanErr := make(chan error)

	// Tạo các routine để thực hiện việc lấy data từ 2 nguồn:
	// -virustotal
	// -otx
	for _, p := range list {
		// Run routine
		go func(i ioc.IocProvider) {
			data, err := i.Get(limit)
			if err != nil {
				chanErr <- err
				return
			}
			// Đẩy dữ liệu vào channel
			chanData <- data.Sha256
		}(p)
	}

	// Lấy dữ liệu từ các channel (nếu có)
	var result []string
	for i:=0; i < len(list); i++ {
		select {
		case sha256 := <-chanData:
			result = append(result, sha256)
		case err := <-chanErr:
			panic(err)
		}
	}

	return result[0], nil
}

func main()  {
	// Tạo provider để gọi api virustotal.com
	virustotal := ioc.VirustotalProvider{
		APIKey: os.Getenv("VIRUSTOTAL_API_KEY"),
		URL: "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files",
	}

	// Tạo provider để gọi api otx.alienvault.com
	/*otx := ioc.OtxProvider{
		APIKey: os.Getenv("OTX_API_KEY"),
		URL:    "https://otx.alienvault.com/api/v1/pulses/subscribed",
	}*/

	// Danh sách chứa các service
	iocList := ProviderList{
		virustotal,
		//otx,
	}

	// Xử lý Rest API sử dụng thư viện Gorilla Mux
	r := mux.NewRouter()
	r.HandleFunc("/api/ioc/{limit}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		limit := vars["limit"]

		// Lấy data
		sha256, _ := iocList.iocData(limit)

		result := IocData{
			Sha256: sha256,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}).Methods("GET")

	port := 9000
	fmt.Printf("Server is listening at port: %d\n", port)
	log.Fatal(http.ListenAndServe(":"+fmt.Sprint(port), r))

}
