module ovara.proxy

go 1.25.6

require (
	golang.org/x/sys v0.44.0
	ovara.runtime.gateway v0.0.0
)

require (
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

replace ovara.runtime.gateway => ../runtime/gateway
