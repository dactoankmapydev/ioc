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

// Lấy dữ liệu
func (list ProviderList) iocData(limit string) ([]ioc.VrttInfo, error) {
	// Tạo channel để hứng data và error trả về từ routine
	chanData := make(chan []ioc.VrttInfo)
	chanErr := make(chan error)

	// Tạo các routine để thực hiện việc lấy data từ 2 nguồn:
	// -virustotal
	// -otx
	for _, p := range list {
		// Run routine
		go func(i ioc.IocProvider) {
			data, err := i.GetHuntingNotificationFiles(limit)
			if err != nil {
				chanErr <- err
				return
			}
			// Đẩy dữ liệu vào channel
			chanData <- data
		}(p)
	}

	// Lấy dữ liệu từ các channel (nếu có)
	var result []ioc.VrttInfo
	for i:=0; i < len(list); i++ {
		select {
		case item := <-chanData:
			for _, value := range item {
				result = append(result, value)
			}
		case err := <-chanErr:
			panic(err)
		}
	}
	return result, nil
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

	// Lấy dữ liệu từ channel
	//data, _ := iocList.iocData("3")
	//fmt.Println(data)

	// Xử lý Rest API sử dụng thư viện Gorilla Mux
	r := mux.NewRouter()

	// Vrtt api
	r.HandleFunc("/api/ioc/vrtt/{limit}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		limit := vars["limit"]

		// Lấy data
		data, _ := iocList.iocData(limit)
		results := make([]ioc.VrttInfo, 0)
        for _, value := range data {
        	results = append(results, ioc.VrttInfo{
        		Name: value.Name,
        		Sha256: value.Sha256,
        		Sha1: value.Sha1,
        		Md5: value.Md5,
        		FileType: value.FileType,
        		FirstSubmit: value.FirstSubmit,
        		NotificationDate: value.NotificationDate,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}).Methods("GET")

	port := 9000
	fmt.Printf("Server is listening at port: %d\n", port)
	log.Fatal(http.ListenAndServe(":"+fmt.Sprint(port), r))

}
