package main

type RequiredFields struct {
	Domain        string `json:"domain"`
	Serial_number string `json:"serial_number"`
	Country       string `json:"country"`
}

type Cert struct {
	PrivateKey string         `json:"private_key"`
	Data       RequiredFields `json:"required_data"`
}
