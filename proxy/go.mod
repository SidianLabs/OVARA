module ovara.proxy

go 1.26.0

require (
	golang.org/x/sys v0.49.0
	ovara.runtime.gateway v0.0.0
)

require (
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

replace ovara.runtime.gateway => ../runtime/gateway
