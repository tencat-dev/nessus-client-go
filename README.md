# Nessus SDK for Go

A lightweight Go SDK for interacting with the Nessus API.

## 📦 Installation

```bash
go get -u github.com/tencat-dev/nessus-sdk-go
```

## 🔧 Usage

```go
package main

import (
 "fmt"
 "log"

 nessus "github.com/tencat-dev/nessus-sdk-go"
)

func main() {
 // Create a new client with API URL
 client, err := nessus.NewClient(
  nessus.WithApiURL("https://localhost:8834"),
 )
 if err != nil {
  fmt.Println("failed to create client: ", err)
  return
 }

 status, err := client.ServerStatus()
 if err != nil {
  log.Fatalf("failed to get server status: %v", err)
 }
 fmt.Println("Server status: ", status)
}
```

## 📌 Roadmap

### Editors

- [x] List
- [ ] Details

### Folders

- [x] Create
- [x] Delete
- [x] Edit
- [x] List

### Plugins

- [x] Families
- [x] Family Details
- [x] Plugin Details

### Scans

- [x] Attachment Prepare
- [x] Configure
- [x] Copy
- [x] Create
- [x] Delete
- [x] Delete Bulk
- [x] Delete History
- [x] Details
- [ ] Export Formats
- [ ] Export Download
- [ ] Export Request
- [x] Export Status
- [x] Host Details
- [ ] Import
- [x] Kill
- [x] Launch
- [x] List
- [x] Pause
- [x] Plugin Output
- [x] Read Status
- [x] Resume
- [x] Schedule
- [x] Stop
- [x] Timezones

### Server

- [x] Properties
- [x] Status

### Session

- [x] Create
- [x] Destroy
- [x] Edit
- [x] Get
- [x] Password
- [x] Keys

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📄 License

[MIT License](./LICENSE)
