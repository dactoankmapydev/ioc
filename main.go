package main

import (
	"fmt"
	"github.com/joho/godotenv"
	ioc "ioc-provider/ioc"
	"ioc-provider/model"
	"log"
	"os"
)
// Danh sách các Provider
type ProviderList []ioc.IocProvider

// Lấy dữ liệu
func (list ProviderList) iocData() ([]model.VrttInfo, error) {
	// Tạo channel để hứng data và error trả về từ routine
	chanData := make(chan []model.VrttInfo)
	chanErr := make(chan error)

	// Tạo các routine để thực hiện việc lấy data từ nguồn virustotal:
	for _, p := range list {
		// Run routine
		go func(i ioc.IocProvider) {
			data, err := i.GetHuntingNotificationFiles()
			if err != nil {
				chanErr <- err
				return
			}
			// Đẩy dữ liệu vào channel
			chanData <- data
		}(p)
	}

	// Lấy dữ liệu từ các channel (nếu có)
	var result []model.VrttInfo
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

func init() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("not environment variable")
	}
}

func main()  {
	// Tạo provider để gọi api virustotal.com
	virustotal := ioc.VirustotalProvider{
		APIKey: os.Getenv("VIRUSTOTAL_API_KEY"),
	}

	// Danh sách chứa các service
	iocList := ProviderList{
		virustotal,
		//otx,
	}

	data, _ := iocList.iocData()
	results := make([]model.VrttInfo, 0)
	for _, value := range data {
		results = append(results, model.VrttInfo{
			Name: value.Name,
			Sha256: value.Sha256,
			Sha1: value.Sha1,
			Md5: value.Md5,
			FileType: value.FileType,
			FirstSubmit: value.FirstSubmit,
			NotificationDate: value.NotificationDate,
			Tags: value.Tags,
			EnginesDetected: value.EnginesDetected,
			Detected: value.Detected,
			Point: value.Point,
		})
	}
	fmt.Println("results main->", results)

    /*
	// Xử lý Rest API sử dụng thư viện Gorilla Mux
	r := mux.NewRouter()
	// Vrtt api
	r.HandleFunc("/api/ioc/vrtt", func(w http.ResponseWriter, r *http.Request) {
		//vars := mux.Vars(r)
		//limit := vars["limit"]
		// Lấy data
		data, _ := iocList.iocData()
		results := make([]model.VrttInfo, 0)
		for _, value := range data {
			results = append(results, model.VrttInfo{
				Name: value.Name,
				Sha256: value.Sha256,
				Sha1: value.Sha1,
				Md5: value.Md5,
				FileType: value.FileType,
				FirstSubmit: value.FirstSubmit,
				NotificationDate: value.NotificationDate,
				Tags: value.Tags,
				EnginesDetected: value.EnginesDetected,
				Detected: value.Detected,
				Point: value.Point,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}).Methods("GET")
	port := 9000
	fmt.Printf("Server is listening at port: %d\n", port)
	log.Fatal(http.ListenAndServe(":" + fmt.Sprint(port), r))*/
}
