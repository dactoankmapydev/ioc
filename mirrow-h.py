package model

type Compromised struct {
	UID string `json:"uid"`
	HostName string `json:"hostname"`
	Src string `json:"src"`
	VictimHash string `json:"victim_hash"`
	CreationDate int `json:"creation_date"`
	TimeStamp int `json:"timestamp"`
	Country string `json:"country"`
}

