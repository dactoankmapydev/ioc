package main

import (
	"github.com/joho/godotenv"
	"ioc-provider/crawler"
	ioc "ioc-provider/repository"
	"log"
	"os"
)

// Danh sách các Provider
type ProviderList []ioc.IocRepo

func init() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("not environment variable")
	}
}

func (list ProviderList) info() {
	for _, p := range list {
		func(provider ioc.IocRepo) {
			provider.LiveHunting()
			//provider.Subscribed()
		}(p)
	}
}

func main()  {

	// Tạo provider để gọi api virustotal
	virustotal := crawler.VirustotalProvider{
		APIKey: os.Getenv("VIRUSTOTAL_API_KEY"),
	}

	// Tạo provider để gọi api otx
	/*otx := crawler.OtxProvider{
		APIKey: os.Getenv("OTX_API_KEY"),
	}*/

	// Danh sách chứa các service
	iocList := ProviderList{
		virustotal,
		//otx,
	}
	iocList.info()
}
