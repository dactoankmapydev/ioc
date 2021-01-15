package main

import (
	"github.com/joho/godotenv"
	ioc "ioc-provider/ioc"
	"log"
	"os"
)
// Danh sách các Provider
type ProviderList []ioc.IocProvider

func init() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("not environment variable")
	}
}

func (list ProviderList) info() {
	for _, p := range list {
		func(provider ioc.IocProvider) {
			provider.GetHuntingNotificationFiles()
		}(p)
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
	}
	iocList.info()
}
