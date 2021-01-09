package ioc

// IocProvider là interface để service implement các hàm
type IocProvider interface {
	//GetHuntingNotificationFiles(limit, cursor, filter string) (IocInfo, error)
	//GetPulsesSubscribed(limit, page, modifiedSince string) (IocInfo, error)
	Get(limit string) (IocInfo, error)
}

type IocInfo struct {
	Name string
	Sha256 string
	Sha1 string
	Md5 string
	Tags []string
	FirstSubmit string
	NotificationDate string
	FileType string
}
