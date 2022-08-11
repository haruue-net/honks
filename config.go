package main

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	Listen     string   `json:"listen"`
	Timeout    int      `json:"timeout"`
	DisableUDP bool     `json:"disable_udp"`
	Users      []User   `json:"users"`
	LogLevel   LogLevel `json:"log_level"`
}
