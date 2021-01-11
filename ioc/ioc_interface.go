package ioc

// IocProvider là interface để service implement các hàm
type IocProvider interface {
	//GetHuntingNotificationFiles(limit, cursor, filter string) (IocInfo, error)
	//GetPulsesSubscribed(limit, page, modifiedSince string) (IocInfo, error)
	GetHuntingNotificationFiles(limit string) ([]VrttInfo, error)
	//GetPulsesSubscribed(limit string) ([]IocInfo, error)
}

type VrttInfo struct {
	Name string
	Sha256 string
	Sha1 string
	Md5 string
	FirstSubmit string
	NotificationDate string
	FileType string
	Tags []string
	LastAnalysisResults []string
}

type OtxInfo struct {
	PulseId string
	PulseName string
	IndicatorsId string
	IndicatorName string
	IndicatorType string
	Created string
	Modified string
	NextPage string
	Tags []string
}
