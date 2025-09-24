# Nessus SDK for Go

A lightweight Go SDK for interacting with the Nessus API.

## 📦 Installation

```bash
go get -u github.com/anhnmt/nessus-sdk-go
```

## 🔧 Usage

```go
package main

import (
 "fmt"
 "log"

 nessus "github.com/anhnmt/nessus-sdk-go"
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

- [ ] List
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

- [ ] Attachment Prepare
- [ ] Configure
- [ ] Copy
- [ ] Create
- [ ] Delete
- [ ] Delete Bulk
- [ ] Delete History
- [ ] Details
- [ ] Export Formats
- [ ] Export Download
- [ ] Export Request
- [ ] Export Status
- [ ] Host Details
- [ ] Import
- [ ] Kill
- [ ] Launch
- [ ] List
- [ ] Pause
- [ ] Plugin Output
- [ ] Read Status
- [ ] Resume
- [ ] Schedule
- [ ] Stop
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
