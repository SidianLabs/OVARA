module ovara.runtime.gateway

go 1.25.6

require github.com/google/uuid v1.6.0

require (
	github.com/fsnotify/fsnotify v1.10.1
	ovara.identity v0.0.0
)

require golang.org/x/sys v0.13.0 // indirect

replace ovara.identity => ../../identity
